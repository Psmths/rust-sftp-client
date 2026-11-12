//! Recursive name search below a folder, local or remote, in the background.
//!
//! A [`Search`] walks the tree breadth-first and streams matches back; it
//! stops when dropped. Symbolic links are listed but never followed, so a
//! link cannot send the walk in a loop. Hidden items (and everything inside
//! hidden folders) are skipped unless they are shown.

use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
};

use tokio::runtime::Handle;

use crate::{
    connection::SftpConnection,
    session::{LocalEntry, RemoteEntry},
};

/// Most matches kept; the walk stops there.
pub const MAX_RESULTS: usize = 5000;
/// Most folders a remote search lists (each is a network round trip).
const MAX_REMOTE_FOLDERS: usize = 10_000;

/// What a search was started for; a different key needs a new search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchKey {
    /// Lowercased text the names must contain.
    pub query: String,
    /// Folder searched below.
    pub root: String,
    pub show_hidden: bool,
}

enum Update<E> {
    Found(Vec<E>),
    Done { truncated: bool },
}

pub struct Search<E> {
    pub key: SearchKey,
    pub results: Vec<E>,
    pub done: bool,
    /// Stopped early at [`MAX_RESULTS`] (or the remote folder limit).
    pub truncated: bool,
    rx: mpsc::Receiver<Update<E>>,
    cancel: Arc<AtomicBool>,
}

impl<E> Search<E> {
    fn new(key: SearchKey) -> (Self, mpsc::Sender<Update<E>>, Arc<AtomicBool>) {
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let search = Self { key, results: Vec::new(), done: false, truncated: false, rx, cancel: Arc::clone(&cancel) };
        (search, tx, cancel)
    }

    /// Takes in what the walk has found since the last call.
    pub fn poll(&mut self) {
        while let Ok(update) = self.rx.try_recv() {
            match update {
                Update::Found(mut found) => self.results.append(&mut found),
                Update::Done { truncated } => {
                    self.done = true;
                    self.truncated = truncated;
                }
            }
        }
    }
}

impl<E> Drop for Search<E> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Whether a local item is hidden: a dot name, or (Windows) the hidden attribute.
pub fn is_hidden_local(name: &str, metadata: Option<&fs::Metadata>) -> bool {
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        if metadata.is_some_and(|meta| meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0) {
            return true;
        }
    }
    #[cfg(not(windows))]
    let _ = metadata;
    false
}

/// Starts a search below the local folder `root` on its own thread.
pub fn local(root: PathBuf, key: SearchKey) -> Search<LocalEntry> {
    let (search, tx, cancel) = Search::new(key.clone());
    std::thread::spawn(move || {
        let mut found_total = 0;
        let mut truncated = false;
        let mut folders: VecDeque<(PathBuf, String)> = VecDeque::from([(root, String::new())]);
        'walk: while let Some((folder, relative)) = folders.pop_front() {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let Ok(reader) = fs::read_dir(&folder) else { continue };
            let mut found = Vec::new();
            for item in reader.flatten() {
                let name = item.file_name().to_string_lossy().into_owned();
                // DirEntry metadata does not follow symbolic links.
                let metadata = item.metadata().ok();
                if !key.show_hidden && is_hidden_local(&name, metadata.as_ref()) {
                    continue;
                }
                let is_dir = item.file_type().is_ok_and(|kind| kind.is_dir());
                let path = item.path();
                if name.to_lowercase().contains(&key.query) {
                    found.push(LocalEntry {
                        name: name.clone(),
                        path: path.clone(),
                        dir: is_dir,
                        size: metadata.as_ref().map_or(0, fs::Metadata::len),
                        modified: metadata
                            .as_ref()
                            .and_then(|meta| meta.modified().ok())
                            .map(crate::app::format_iso8601)
                            .unwrap_or_else(|| "—".into()),
                        hidden: is_hidden_local(&name, metadata.as_ref()),
                        folder: relative.clone(),
                    });
                    found_total += 1;
                    if found_total >= MAX_RESULTS {
                        truncated = true;
                        let _ = tx.send(Update::Found(std::mem::take(&mut found)));
                        break 'walk;
                    }
                }
                if is_dir {
                    let child = if relative.is_empty() {
                        name
                    } else {
                        format!("{relative}{}{name}", std::path::MAIN_SEPARATOR)
                    };
                    folders.push_back((path, child));
                }
            }
            if !found.is_empty() && tx.send(Update::Found(found)).is_err() {
                return;
            }
        }
        let _ = tx.send(Update::Done { truncated });
    });
    search
}

/// Starts a search below the remote folder `root` (listing through the
/// rsftp-turbo helper when available, else SFTP).
pub fn remote(runtime: &Handle, connection: Arc<SftpConnection>, root: String, key: SearchKey) -> Search<RemoteEntry> {
    let (search, tx, cancel) = Search::new(key.clone());
    runtime.spawn(async move {
        let mut found_total = 0;
        let mut listed = 0;
        let mut truncated = false;
        let mut folders: VecDeque<(String, String)> = VecDeque::from([(root, String::new())]);
        'walk: while let Some((folder, relative)) = folders.pop_front() {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if listed >= MAX_REMOTE_FOLDERS {
                truncated = true;
                break;
            }
            listed += 1;
            let Ok((folder, entries)) = connection.list_directory(&folder).await else { continue };
            let mut found = Vec::new();
            for entry in entries {
                if !key.show_hidden && entry.name.starts_with('.') {
                    continue;
                }
                let path = crate::app::join_remote(&folder, &entry.name);
                if entry.name.to_lowercase().contains(&key.query) {
                    found.push(RemoteEntry {
                        name: entry.name.clone(),
                        path: path.clone(),
                        dir: entry.dir,
                        size: entry.size,
                        modified: entry.mtime.map(|time| crate::app::format_unix_utc(time as i64)).unwrap_or_else(|| "—".into()),
                        folder: relative.clone(),
                    });
                    found_total += 1;
                    if found_total >= MAX_RESULTS {
                        truncated = true;
                        let _ = tx.send(Update::Found(std::mem::take(&mut found)));
                        break 'walk;
                    }
                }
                // Listings describe symbolic links themselves, so `dir` is false for them.
                if entry.dir {
                    let child = if relative.is_empty() { entry.name } else { format!("{relative}/{}", entry.name) };
                    folders.push_back((path, child));
                }
            }
            if !found.is_empty() && tx.send(Update::Found(found)).is_err() {
                return;
            }
        }
        let _ = tx.send(Update::Done { truncated });
    });
    search
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(search: &mut Search<LocalEntry>) {
        for _ in 0..500 {
            search.poll();
            if search.done {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("search did not finish");
    }

    #[test]
    fn local_search_finds_nested_matches_and_skips_hidden_folders() {
        let root = std::env::temp_dir().join(format!("rsftp-search-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join(".secret")).unwrap();
        fs::write(root.join("a/b/Report.TXT"), b"x").unwrap();
        fs::write(root.join("a/notes.md"), b"x").unwrap();
        fs::write(root.join(".secret/report-old.txt"), b"x").unwrap();
        fs::write(root.join(".report"), b"x").unwrap();

        let key = |show_hidden| SearchKey { query: "report".into(), root: String::new(), show_hidden };
        let mut search = local(root.clone(), key(false));
        wait(&mut search);
        let names: Vec<(String, String)> = search.results.iter().map(|entry| (entry.folder.clone(), entry.name.clone())).collect();
        let nested = format!("a{}b", std::path::MAIN_SEPARATOR);
        assert_eq!(names, vec![(nested, "Report.TXT".to_owned())]);
        assert!(!search.truncated);

        let mut search = local(root.clone(), key(true));
        wait(&mut search);
        let mut names: Vec<String> = search.results.iter().map(|entry| entry.name.clone()).collect();
        names.sort();
        assert_eq!(names, [".report", "Report.TXT", "report-old.txt"]);
        assert!(search.results.iter().find(|entry| entry.name == ".report").unwrap().hidden);
        fs::remove_dir_all(&root).unwrap();
    }
}
