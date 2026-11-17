//! Updates from the project's GitHub releases.
//!
//! The release workflow signs `SHA256SUMS.txt` with an ed25519 key whose public
//! half is built in below (`SHA256SUMS.txt.sig`). An update is installed only if
//! that signature is valid and the downloaded program matches its checksum, so
//! a tampered release or download is refused.
//!
//! Network work runs on background threads; the app polls [`Updater`] each frame.

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{mpsc, OnceLock},
    time::{Duration, SystemTime},
};

use eframe::egui;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROJECT_URL: &str = "https://github.com/Psmths/rust-sftp-client";
pub const RELEASES_URL: &str = "https://github.com/Psmths/rust-sftp-client/releases";
pub const ISSUES_URL: &str = "https://github.com/Psmths/rust-sftp-client/issues";
const LATEST_RELEASE_API: &str = "https://api.github.com/repos/Psmths/rust-sftp-client/releases/latest";

/// Public half of the release-signing key (ed25519). The private half is the
/// repository's `UPDATE_SIGNING_KEY` Actions secret.
const SIGNING_KEY: [u8; 32] = [
    223, 254, 136, 241, 33, 207, 178, 16, 102, 169, 124, 180, 157, 6, 237, 194,
    3, 13, 245, 28, 224, 197, 249, 222, 69, 14, 176, 176, 155, 122, 225, 209,
];
const CHECKSUMS: &str = "SHA256SUMS.txt";
const SIGNATURE: &str = "SHA256SUMS.txt.sig";

/// Upper bound for a downloaded program (the Windows build is about 22 MB).
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// Automatic checks while the app stays open.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct UpdateSettings {
    /// Check at startup (and daily) and install new versions automatically.
    pub automatic: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self { automatic: true }
    }
}

/// `major.minor.patch` of this build.
pub fn current_version() -> (u64, u64, u64) {
    parse_version(env!("CARGO_PKG_VERSION")).unwrap_or((0, 0, 0))
}

/// CI run number of this build; `None` for a local `cargo build`.
pub fn build_number() -> Option<&'static str> {
    option_env!("RSFTP_BUILD_NUMBER").filter(|build| !build.is_empty())
}

/// Whether this platform has a release build to update to.
pub fn supported() -> bool {
    cfg!(any(windows, all(target_os = "linux", target_arch = "x86_64")))
}

fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.').map(|part| part.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

/// `v0.5.2-build.20` → ((0, 5, 2), Some(20)).
fn parse_tag(tag: &str) -> Option<((u64, u64, u64), Option<u64>)> {
    let rest = tag.strip_prefix('v')?;
    let (version, build) = match rest.split_once("-build.") {
        Some((version, build)) => (version, Some(build.parse().ok()?)),
        None => (rest, None),
    };
    Some((parse_version(version)?, build))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// `0.5.3`
    pub version: String,
    pub build: Option<u64>,
    /// Release page.
    pub url: String,
    pub notes: String,
    assets: Vec<Asset>,
}

impl Release {
    /// `0.5.3 (build 21)`
    pub fn label(&self) -> String {
        match self.build {
            Some(build) => format!("{} (build {build})", self.version),
            None => self.version.clone(),
        }
    }

    fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.name == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Asset {
    name: String,
    #[serde(rename = "browser_download_url")]
    url: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<Asset>,
}

fn release_from_api(json: &str) -> Result<Release, String> {
    let api: ApiRelease = serde_json::from_str(json).map_err(|error| format!("unexpected answer from GitHub: {error}"))?;
    let (version, build) = parse_tag(&api.tag_name).ok_or_else(|| format!("unexpected release tag {}", api.tag_name))?;
    Ok(Release {
        version: format!("{}.{}.{}", version.0, version.1, version.2),
        build,
        url: api.html_url,
        notes: api.body.unwrap_or_default(),
        assets: api.assets,
    })
}

/// Release file holding this platform's program.
fn program_asset_name(version: &str) -> String {
    if cfg!(windows) {
        format!("rust-sftp-client-{version}-windows-x86_64.exe")
    } else {
        format!("rust-sftp-client-{version}-linux-x86_64.tar.gz")
    }
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .user_agent(format!("rust-sftp-client/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn download(agent: &ureq::Agent, url: &str, what: &str) -> Result<Vec<u8>, String> {
    let mut response = agent.get(url).call().map_err(|error| format!("could not download {what}: {error}"))?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD_BYTES)
        .read_to_vec()
        .map_err(|error| format!("could not download {what}: {error}"))
}

/// The latest release, if it is newer than this build.
pub fn check() -> Result<Option<Release>, String> {
    let mut response = agent(Duration::from_secs(30))
        .get(LATEST_RELEASE_API)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|error| format!("could not reach GitHub: {error}"))?;
    let json = response.body_mut().read_to_string().map_err(|error| format!("could not read GitHub's answer: {error}"))?;
    let release = release_from_api(&json)?;
    let newer = parse_version(&release.version).is_some_and(|version| version > current_version());
    Ok(newer.then_some(release))
}

/// Checks the signature of the checksum list, then returns the checksum it
/// lists for `file`.
fn verified_checksum(checksums: &[u8], signature: &[u8], file: &str) -> Result<String, String> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&SIGNING_KEY).map_err(|error| format!("bad built-in signing key: {error}"))?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| "the release signature has the wrong length".to_owned())?;
    key.verify_strict(checksums, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| "the release signature is not valid; the update was not installed".to_owned())?;
    let text = std::str::from_utf8(checksums).map_err(|_| "the checksum list is not text".to_owned())?;
    text.lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(_, name)| name.trim_start().trim_start_matches('*') == file)
        .map(|(hash, _)| hash.to_ascii_lowercase())
        .ok_or_else(|| format!("{file} is not in the release's checksum list"))
}

/// Takes the program out of the Linux release archive (it holds one file).
fn unpack_tar_gz(archive: &[u8]) -> Result<Vec<u8>, String> {
    let mut entries = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in entries.entries().map_err(|error| format!("bad release archive: {error}"))? {
        let mut entry = entry.map_err(|error| format!("bad release archive: {error}"))?;
        if entry.header().entry_type().is_file() {
            let mut program = Vec::new();
            entry.read_to_end(&mut program).map_err(|error| format!("bad release archive: {error}"))?;
            return Ok(program);
        }
    }
    Err("the release archive holds no program".into())
}

/// Path of this program, recorded at startup: on Linux, `current_exe` gains a
/// " (deleted)" suffix once the file has been replaced.
pub fn program_path() -> Option<&'static Path> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| std::env::current_exe().ok()).as_deref()
}

/// Downloads `release`, checks it, and replaces this program's file with it.
/// The running program keeps going; the new version starts next time.
pub fn install(release: &Release) -> Result<(), String> {
    if !supported() {
        return Err("there is no release build for this platform".into());
    }
    let program_name = program_asset_name(&release.version);
    let program = release.asset(&program_name).ok_or_else(|| format!("the release has no {program_name}"))?;
    let (Some(checksums), Some(signature)) = (release.asset(CHECKSUMS), release.asset(SIGNATURE)) else {
        return Err("this release is not signed, so it cannot be installed automatically; download it from the releases page".into());
    };
    let agent = agent(Duration::from_secs(15 * 60));
    let checksums = download(&agent, &checksums.url, CHECKSUMS)?;
    let signature = download(&agent, &signature.url, SIGNATURE)?;
    let expected = verified_checksum(&checksums, &signature, &program_name)?;
    let downloaded = download(&agent, &program.url, &program_name)?;
    let actual: String = Sha256::digest(&downloaded).iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != expected {
        return Err(format!("{program_name} does not match its checksum; the update was not installed"));
    }
    let new_program = if cfg!(windows) { downloaded } else { unpack_tar_gz(&downloaded)? };
    replace_program(&new_program)
}

fn replace_program(new_program: &[u8]) -> Result<(), String> {
    let staged = std::env::temp_dir().join(format!("rust-sftp-client-update-{}{}", std::process::id(), std::env::consts::EXE_SUFFIX));
    std::fs::write(&staged, new_program).map_err(|error| format!("could not save the update: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("could not save the update: {error}"))?;
    }
    let result = self_replace::self_replace(&staged).map_err(|error| {
        let location = program_path().map(|path| path.display().to_string()).unwrap_or_else(|| "the program".into());
        format!("could not replace {location}: {error}. If it was installed into a system folder, update it the way it was installed")
    });
    let _ = std::fs::remove_file(&staged);
    result
}

/// Starts the (updated) program again; the caller then closes this one.
pub fn restart() -> Result<(), String> {
    let path = program_path().ok_or_else(|| "the program's location is unknown".to_owned())?;
    std::process::Command::new(path).spawn().map(drop).map_err(|error| format!("could not start {}: {error}", path.display()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Idle,
    Checking,
    UpToDate,
    Available(Release),
    Installing(Release),
    /// Installed; takes effect when the program is restarted.
    Installed(Release),
    Failed(String),
}

enum Outcome {
    Checked(Result<Option<Release>, String>),
    Installed(Release, Result<(), String>),
}

/// Something the app should tell the user about after [`Updater::poll`].
pub enum Notice {
    /// A new version was installed automatically.
    Installed(Release),
    /// An automatic update found a new version but could not install it.
    AvailableNotInstalled(Release, String),
}

pub struct Updater {
    pub status: Status,
    pub last_checked: Option<SystemTime>,
    /// Install what the current check finds (automatic updates).
    install_found: bool,
    receiver: Option<mpsc::Receiver<Outcome>>,
    /// Woken when background work finishes.
    ctx: Option<egui::Context>,
}

impl Default for Updater {
    fn default() -> Self {
        // Record the program's path before anything can replace it.
        let _ = program_path();
        Self { status: Status::Idle, last_checked: None, install_found: false, receiver: None, ctx: None }
    }
}

impl Updater {
    pub fn busy(&self) -> bool {
        matches!(self.status, Status::Checking | Status::Installing(_))
    }

    /// Looks for a newer release; with `install`, installs it as well.
    pub fn check(&mut self, ctx: &egui::Context, install: bool) {
        if self.busy() || matches!(self.status, Status::Installed(_)) {
            return;
        }
        self.status = Status::Checking;
        self.install_found = install;
        self.ctx = Some(ctx.clone());
        self.spawn(|sender| {
            let _ = sender.send(Outcome::Checked(check()));
        });
    }

    pub fn install(&mut self, ctx: &egui::Context) {
        let Status::Available(release) = &self.status else { return };
        let release = release.clone();
        self.ctx = Some(ctx.clone());
        self.start_install(release);
    }

    fn start_install(&mut self, release: Release) {
        self.status = Status::Installing(release.clone());
        self.spawn(move |sender| {
            let result = install(&release);
            let _ = sender.send(Outcome::Installed(release, result));
        });
    }

    /// Whether the daily automatic check is due.
    pub fn check_due(&self) -> bool {
        !self.busy()
            && !matches!(self.status, Status::Installed(_))
            && self.last_checked.is_none_or(|checked| checked.elapsed().map_or(true, |since| since >= CHECK_INTERVAL))
    }

    fn spawn(&mut self, work: impl FnOnce(mpsc::Sender<Outcome>) + Send + 'static) {
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            work(sender);
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
    }

    /// Picks up finished background work.
    pub fn poll(&mut self) -> Option<Notice> {
        let outcome = self.receiver.as_ref()?.try_recv().ok()?;
        self.receiver = None;
        match outcome {
            Outcome::Checked(result) => {
                self.last_checked = Some(SystemTime::now());
                match result {
                    // Local builds are never replaced automatically.
                    Ok(Some(release)) if self.install_found && build_number().is_some() => {
                        self.start_install(release);
                        None
                    }
                    Ok(Some(release)) => {
                        self.install_found = false;
                        self.status = Status::Available(release);
                        None
                    }
                    Ok(None) => {
                        self.status = Status::UpToDate;
                        None
                    }
                    Err(error) => {
                        self.status = Status::Failed(error);
                        None
                    }
                }
            }
            Outcome::Installed(release, result) => {
                let automatic = std::mem::take(&mut self.install_found);
                match result {
                    Ok(()) => {
                        self.status = Status::Installed(release.clone());
                        automatic.then_some(Notice::Installed(release))
                    }
                    Err(error) => {
                        self.status = Status::Failed(error.clone());
                        automatic.then_some(Notice::AvailableNotInstalled(release, error))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn parses_release_tags() {
        assert_eq!(parse_tag("v0.5.2-build.20"), Some(((0, 5, 2), Some(20))));
        assert_eq!(parse_tag("v1.0.0"), Some(((1, 0, 0), None)));
        assert_eq!(parse_tag("0.5.2"), None);
        assert_eq!(parse_tag("v0.5-build.3"), None);
        assert_eq!(parse_tag("v0.5.2-build.x"), None);
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(parse_version("0.10.0").unwrap() > parse_version("0.9.9").unwrap());
        assert!(parse_version("1.0.0").unwrap() > parse_version("0.99.99").unwrap());
        assert_eq!(parse_version("0.5"), None);
        assert_eq!(parse_version("0.5.2.1"), None);
    }

    #[test]
    fn reads_githubs_release_answer() {
        let json = r#"{"tag_name":"v0.6.0-build.30","html_url":"https://example/r","body":"Notes",
            "assets":[{"name":"SHA256SUMS.txt","browser_download_url":"https://example/sums","size":1}]}"#;
        let release = release_from_api(json).unwrap();
        assert_eq!(release.version, "0.6.0");
        assert_eq!(release.build, Some(30));
        assert_eq!(release.label(), "0.6.0 (build 30)");
        assert_eq!(release.asset(CHECKSUMS).unwrap().url, "https://example/sums");
        assert!(release.asset(SIGNATURE).is_none());
    }

    #[test]
    fn checksums_need_a_valid_signature() {
        // A different key than the built-in one: its signatures must be refused.
        let other = SigningKey::from_bytes(&[7; 32]);
        let sums = b"abc123  rust-sftp-client-0.6.0-windows-x86_64.exe\n";
        let signature = other.sign(sums).to_bytes();
        assert!(verified_checksum(sums, &signature, "rust-sftp-client-0.6.0-windows-x86_64.exe").is_err());
        assert!(verified_checksum(sums, &[0; 10], "x").is_err());
    }

    #[test]
    fn accepts_checksums_signed_with_the_release_key() {
        // Signed with the release key by `openssl pkeyutl -sign -rawin`, as the
        // release workflow does.
        let sums = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  rust-sftp-client-9.9.9-windows-x86_64.exe\n";
        let signature = [
            72, 110, 100, 223, 109, 208, 246, 247, 89, 206, 47, 218, 31, 13, 160, 115, 108, 94, 104, 76, 222, 250, 154, 110,
            17, 140, 184, 152, 86, 61, 56, 236, 169, 173, 85, 7, 152, 241, 51, 176, 158, 82, 179, 132, 184, 48, 104, 66,
            233, 246, 223, 137, 144, 212, 56, 199, 104, 96, 69, 108, 244, 78, 140, 11,
        ];
        let name = "rust-sftp-client-9.9.9-windows-x86_64.exe";
        assert_eq!(verified_checksum(sums, &signature, name).unwrap(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(verified_checksum(sums, &signature, "something-else").is_err());
        let mut tampered = sums.to_vec();
        tampered[0] = b'f';
        assert!(verified_checksum(&tampered, &signature, name).is_err());
    }

    #[test]
    fn unpacks_the_program_from_a_release_archive() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, "rust-sftp-client-0.6.0", &b"hello"[..]).unwrap();
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        assert_eq!(unpack_tar_gz(&gz.finish().unwrap()).unwrap(), b"hello");
    }
}
