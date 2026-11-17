//! Bookmarked folders of the local and remote panes, kept in `settings.json`.
//!
//! Local bookmarks are shared by all sessions. Remote bookmarks belong to a
//! server login (`user@host:port`, see `credentials::key`), so profiles that
//! log in to the same account share them.

use std::{collections::BTreeMap, path::{Path, PathBuf}};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Bookmarks {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub local: Vec<PathBuf>,
    /// Remote folders by server login.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub remote: BTreeMap<String, Vec<String>>,
}

impl Bookmarks {
    pub fn is_local(&self, path: &Path) -> bool {
        self.local.iter().any(|bookmark| bookmark == path)
    }

    /// Adds `path` if it is not bookmarked, removes it if it is.
    pub fn toggle_local(&mut self, path: &Path) {
        if self.is_local(path) {
            self.local.retain(|bookmark| bookmark != path);
        } else {
            self.local.push(path.to_path_buf());
            self.local.sort();
        }
    }

    pub fn remote_for(&self, login: &str) -> &[String] {
        self.remote.get(login).map(Vec::as_slice).unwrap_or_default()
    }

    pub fn is_remote(&self, login: &str, path: &str) -> bool {
        let path = normalize_remote(path);
        self.remote_for(login).iter().any(|bookmark| *bookmark == path)
    }

    /// Adds `path` to the login's bookmarks if missing, removes it otherwise.
    pub fn toggle_remote(&mut self, login: &str, path: &str) {
        let path = normalize_remote(path);
        let list = self.remote.entry(login.to_owned()).or_default();
        if list.contains(&path) {
            list.retain(|bookmark| *bookmark != path);
            if list.is_empty() {
                self.remote.remove(login);
            }
        } else {
            list.push(path);
            list.sort();
        }
    }
}

/// `/srv/www/` and `/srv/www` are the same folder; the root stays `/`.
fn normalize_remote(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() && path.starts_with('/') { "/".to_owned() } else { trimmed.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_toggle_adds_sorted_and_removes() {
        let mut bookmarks = Bookmarks::default();
        bookmarks.toggle_local(Path::new("/home/b"));
        bookmarks.toggle_local(Path::new("/home/a"));
        assert_eq!(bookmarks.local, vec![PathBuf::from("/home/a"), PathBuf::from("/home/b")]);
        assert!(bookmarks.is_local(Path::new("/home/a")));
        bookmarks.toggle_local(Path::new("/home/a"));
        assert_eq!(bookmarks.local, vec![PathBuf::from("/home/b")]);
    }

    #[test]
    fn remote_bookmarks_are_per_login_and_ignore_trailing_slashes() {
        let mut bookmarks = Bookmarks::default();
        bookmarks.toggle_remote("alice@host:22", "/srv/www/");
        bookmarks.toggle_remote("alice@host:22", "/");
        assert!(bookmarks.is_remote("alice@host:22", "/srv/www"));
        assert!(!bookmarks.is_remote("bob@host:22", "/srv/www"));
        assert_eq!(bookmarks.remote_for("alice@host:22"), ["/", "/srv/www"]);
        bookmarks.toggle_remote("alice@host:22", "/srv/www");
        bookmarks.toggle_remote("alice@host:22", "/");
        assert!(bookmarks.remote.is_empty());
    }

    #[test]
    fn empty_bookmarks_round_trip_through_json() {
        let json = serde_json::to_string(&Bookmarks::default()).unwrap();
        assert_eq!(json, "{}");
        assert_eq!(serde_json::from_str::<Bookmarks>(&json).unwrap(), Bookmarks::default());
    }
}
