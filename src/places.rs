//! Local "places": the user's home directory and the drives / mounted
//! filesystems shown in the local pane's drive selector.

use std::path::{Path, PathBuf};

/// The user's home directory (`HOME`, or `USERPROFILE` on Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drive {
    /// Text shown in the drop-down, e.g. `C:\` or `/mnt/data (nvme0n1p2)`.
    pub label: String,
    /// Root of the drive / mount point.
    pub path: PathBuf,
}

/// Index of the drive whose root is the longest prefix of `path`.
pub fn containing(drives: &[Drive], path: &Path) -> Option<usize> {
    drives
        .iter()
        .enumerate()
        .filter(|(_, drive)| path.starts_with(&drive.path))
        .max_by_key(|(_, drive)| drive.path.components().count())
        .map(|(index, _)| index)
}

/// Drive letters that currently exist (`A:\` … `Z:\`).
#[cfg(windows)]
pub fn list() -> Vec<Drive> {
    (b'A'..=b'Z')
        .map(|letter| format!("{}:\\", letter as char))
        .filter(|root| Path::new(root).exists())
        .map(|root| Drive { label: root.clone(), path: PathBuf::from(root) })
        .collect()
}

/// The root filesystem plus every mounted volume under `/Volumes`.
#[cfg(target_os = "macos")]
pub fn list() -> Vec<Drive> {
    let mut drives = vec![Drive { label: "/".into(), path: PathBuf::from("/") }];
    if let Ok(entries) = std::fs::read_dir("/Volumes") {
        let mut volumes: Vec<Drive> = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .map(|entry| Drive {
                label: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path(),
            })
            .collect();
        volumes.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
        drives.extend(volumes);
    }
    drives
}

/// Mounted block-device and network filesystems from `/proc/mounts`
/// (or `/etc/mtab`), skipping pseudo filesystems and system-internal mounts.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn list() -> Vec<Drive> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .or_else(|_| std::fs::read_to_string("/etc/mtab"))
        .unwrap_or_default();
    let mut drives = parse_mounts(&mounts);
    if !drives.iter().any(|drive| drive.path == Path::new("/")) {
        drives.insert(0, Drive { label: "/".into(), path: PathBuf::from("/") });
    }
    drives
}

#[cfg(all(unix, not(target_os = "macos")))]
fn parse_mounts(mounts: &str) -> Vec<Drive> {
    const NETWORK: &[&str] = &["nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "fuse.rclone"];
    const HIDDEN_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/run", "/boot", "/efi", "/snap", "/var/lib", "/tmp"];
    const ALLOWED_RUN_PREFIXES: &[&str] = &["/run/media", "/run/mount"];

    let mut drives: Vec<Drive> = Vec::new();
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(device), Some(mount_point), Some(fs_type)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        let device = unescape_mount_field(device);
        let mount_point = unescape_mount_field(mount_point);
        let block_device = device.starts_with("/dev/") && !device.starts_with("/dev/loop");
        let interesting = block_device || NETWORK.contains(&fs_type) || fs_type == "zfs" || fs_type == "fuseblk";
        if !interesting {
            continue;
        }
        let hidden = mount_point != "/"
            && HIDDEN_PREFIXES.iter().any(|prefix| is_under(&mount_point, prefix))
            && !ALLOWED_RUN_PREFIXES.iter().any(|prefix| is_under(&mount_point, prefix));
        if hidden {
            continue;
        }
        let source = if block_device {
            device.trim_start_matches("/dev/").trim_start_matches("mapper/").to_owned()
        } else {
            device.clone()
        };
        let label = if mount_point == "/" { format!("/ ({source})") } else { format!("{mount_point} ({source})") };
        // Later mounts shadow earlier ones on the same mount point (e.g. btrfs subvolumes).
        drives.retain(|drive| drive.path != Path::new(&mount_point));
        drives.push(Drive { label, path: PathBuf::from(mount_point) });
    }
    drives.sort_by(|a, b| a.path.cmp(&b.path));
    drives
}

#[cfg(all(unix, not(target_os = "macos")))]
fn is_under(path: &str, prefix: &str) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// `/proc/mounts` escapes space, tab, newline and backslash as `\ooo` octal.
#[cfg(all(unix, not(target_os = "macos")))]
fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b)) {
            let value = u32::from(bytes[i + 1] - b'0') * 64 + u32::from(bytes[i + 2] - b'0') * 8 + u32::from(bytes[i + 3] - b'0');
            out.push(value.min(255) as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(all(test, unix, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn parses_real_mounts_and_skips_pseudo_filesystems() {
        let mounts = "\
proc /proc proc rw 0 0
/dev/nvme0n1p2 / btrfs rw 0 0
/dev/nvme0n1p2 /home btrfs rw 0 0
/dev/nvme0n1p1 /boot vfat rw 0 0
tmpfs /tmp tmpfs rw 0 0
/dev/sdb1 /run/media/user/USB\\040Stick vfat rw 0 0
/dev/loop0 /snap/core/1 squashfs ro 0 0
server:/export /mnt/nfs nfs4 rw 0 0
";
        let drives = parse_mounts(mounts);
        let paths: Vec<_> = drives.iter().map(|d| d.path.to_string_lossy().into_owned()).collect();
        assert_eq!(paths, vec!["/", "/home", "/mnt/nfs", "/run/media/user/USB Stick"]);
        assert_eq!(drives[0].label, "/ (nvme0n1p2)");
    }

    #[test]
    fn finds_longest_matching_drive() {
        let drives = vec![
            Drive { label: "/".into(), path: "/".into() },
            Drive { label: "/home".into(), path: "/home".into() },
        ];
        assert_eq!(containing(&drives, Path::new("/home/user/docs")), Some(1));
        assert_eq!(containing(&drives, Path::new("/etc")), Some(0));
    }
}
