//! Connection and transfer logging in RFC 5424 syslog format.
//!
//! Every line looks like
//!
//! ```text
//! <13>1 2026-11-08T14:03:12.481Z myhost rust-sftp-client 4242 CONNECT [session@32473 id="1" remote="alice@example.org:22"] Connected
//! ```
//!
//! i.e. `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`,
//! with the timestamp always in UTC. Connection and transfer events share a
//! file: either one combined log, or one log per session when splitting is on.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::PathBuf,
    sync::{Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const APP_NAME: &str = "rust-sftp-client";
const COMBINED_FILE: &str = "rust-sftp-client.log";
/// Facility 1 = user-level messages.
const FACILITY: u8 = 1;
/// Private enterprise number reserved for documentation (RFC 5612).
const SD_ID: &str = "session@32473";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LoggingSettings {
    pub enabled: bool,
    pub log_connections: bool,
    pub log_transfers: bool,
    pub directory: PathBuf,
    /// One file per session, named after the remote.
    pub split_sessions: bool,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            log_connections: true,
            log_transfers: true,
            directory: default_log_dir(),
            split_sessions: false,
        }
    }
}

/// `%LOCALAPPDATA%\rust-sftp-client\logs` on Windows,
/// `~/Library/Logs/rust-sftp-client` on macOS and
/// `$XDG_STATE_HOME/rust-sftp-client/logs` (default `~/.local/state/…`) elsewhere.
pub fn default_log_dir() -> PathBuf {
    let home = crate::places::home_dir().unwrap_or_else(|| PathBuf::from("."));
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Local"))
            .join(APP_NAME)
            .join("logs")
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Logs").join(APP_NAME)
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local").join("state"))
            .join(APP_NAME)
            .join("logs")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Connection,
    Transfer,
}

/// Syslog severities used by the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
}

/// Identifies the session a log line belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLog {
    pub id: u64,
    /// `user@host:port`
    pub remote: String,
    /// When the session started connecting; used in split log file names.
    pub started: SystemTime,
}

pub struct Logger {
    settings: RwLock<LoggingSettings>,
    hostname: String,
    pid: u32,
    last_error: Mutex<Option<String>>,
}

impl Logger {
    pub fn new(settings: LoggingSettings) -> Self {
        Self {
            settings: RwLock::new(settings),
            hostname: hostname(),
            pid: std::process::id(),
            last_error: Mutex::new(None),
        }
    }

    pub fn set_settings(&self, settings: LoggingSettings) {
        if let Ok(mut current) = self.settings.write() {
            *current = settings;
        }
    }

    pub fn log(&self, session: &SessionLog, category: Category, severity: Severity, msgid: &str, message: &str) {
        let Ok(settings) = self.settings.read().map(|settings| settings.clone()) else { return; };
        let wanted = match category {
            Category::Connection => settings.log_connections,
            Category::Transfer => settings.log_transfers,
        };
        if !settings.enabled || !wanted {
            return;
        }
        let line = format_line(SystemTime::now(), &self.hostname, self.pid, severity, msgid, session, message);
        let path = log_file_path(&settings, session);
        let result = fs::create_dir_all(&settings.directory)
            .and_then(|()| OpenOptions::new().create(true).append(true).open(&path))
            .and_then(|mut file| file.write_all(line.as_bytes()));
        if let Err(error) = result {
            if let Ok(mut last) = self.last_error.lock() {
                *last = Some(format!("Could not write log file {}: {error}", path.display()));
            }
        }
    }

    /// The most recent write failure, if any (cleared when taken).
    pub fn take_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|mut last| last.take())
    }
}

/// Where lines for `session` go under the given settings.
pub fn log_file_path(settings: &LoggingSettings, session: &SessionLog) -> PathBuf {
    if settings.split_sessions {
        let name = format!(
            "{}_{}_{}.log",
            sanitize_file_name(&session.remote),
            compact_timestamp(session.started),
            session.id
        );
        settings.directory.join(name)
    } else {
        settings.directory.join(COMBINED_FILE)
    }
}

/// One RFC 5424 line, terminated by `\n`.
pub fn format_line(
    now: SystemTime,
    hostname: &str,
    pid: u32,
    severity: Severity,
    msgid: &str,
    session: &SessionLog,
    message: &str,
) -> String {
    let priority = FACILITY * 8 + severity as u8;
    let message: String = message.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    format!(
        "<{priority}>1 {} {} {APP_NAME} {pid} {} [{SD_ID} id=\"{}\" remote=\"{}\"] {message}\n",
        iso8601_utc(now),
        header_field(hostname, 255),
        header_field(msgid, 32),
        session.id,
        escape_sd_value(&session.remote),
    )
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`
pub fn iso8601_utc(time: SystemTime) -> String {
    let (seconds, millis) = unix_parts(time);
    let (year, month, day, hour, minute, second) = civil(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// `YYYYMMDDTHHMMSSZ`, safe for file names.
fn compact_timestamp(time: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = civil(unix_parts(time).0);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn unix_parts(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_millis()),
        Err(_) => (0, 0),
    }
}

/// Days-from-civil inverse (proleptic Gregorian, UTC).
fn civil(seconds: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day, day_seconds / 3600, (day_seconds % 3600) / 60, day_seconds % 60)
}

/// Header fields are printable US-ASCII without spaces; `-` means "nil".
fn header_field(value: &str, max_len: usize) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max_len)
        .collect();
    if cleaned.is_empty() { "-".into() } else { cleaned }
}

/// Inside SD-PARAM values `"`, `\` and `]` must be escaped.
fn escape_sd_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '"' | '\\' | ']') {
            escaped.push('\\');
        }
        escaped.push(if c.is_control() { ' ' } else { c });
    }
    escaped
}

fn sanitize_file_name(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@') { c } else { '_' })
        .collect();
    if cleaned.is_empty() { "session".into() } else { cleaned }
}

fn hostname() -> String {
    let from_env = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok();
    let from_file = || fs::read_to_string("/etc/hostname").ok().map(|name| name.trim().to_owned());
    from_env.or_else(from_file).filter(|name| !name.is_empty()).unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn session() -> SessionLog {
        SessionLog {
            id: 7,
            remote: "alice@example.org:22".into(),
            started: UNIX_EPOCH + Duration::from_secs(1_762_610_592),
        }
    }

    #[test]
    fn formats_rfc5424_line_in_utc() {
        let now = UNIX_EPOCH + Duration::from_millis(1_762_610_592_481);
        let line = format_line(now, "my host", 42, Severity::Notice, "CONNECT", &session(), "Connected\nnow");
        assert_eq!(
            line,
            "<13>1 2025-11-08T14:03:12.481Z myhost rust-sftp-client 42 CONNECT \
             [session@32473 id=\"7\" remote=\"alice@example.org:22\"] Connected now\n"
        );
    }

    #[test]
    fn escapes_structured_data() {
        assert_eq!(escape_sd_value(r#"a"b\c]d"#), r#"a\"b\\c\]d"#);
    }

    #[test]
    fn names_split_logs_after_the_remote() {
        let settings = LoggingSettings { directory: PathBuf::from("logs"), split_sessions: true, ..Default::default() };
        assert_eq!(
            log_file_path(&settings, &session()),
            PathBuf::from("logs").join("alice@example.org_22_20251108T140312Z_7.log")
        );
        let combined = LoggingSettings { directory: PathBuf::from("logs"), ..Default::default() };
        assert_eq!(log_file_path(&combined, &session()), PathBuf::from("logs").join(COMBINED_FILE));
    }

    #[test]
    fn writes_both_categories_to_the_same_file() {
        let directory = std::env::temp_dir().join(format!("rust-sftp-client-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let logger = Logger::new(LoggingSettings { enabled: true, directory: directory.clone(), ..Default::default() });
        logger.log(&session(), Category::Connection, Severity::Info, "CONNECT", "hello");
        logger.log(&session(), Category::Transfer, Severity::Info, "TRANSFER", "world");
        let contents = fs::read_to_string(directory.join(COMBINED_FILE)).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains(" CONNECT ") && contents.contains(" TRANSFER "));
        logger.set_settings(LoggingSettings { enabled: true, log_transfers: false, directory: directory.clone(), ..Default::default() });
        logger.log(&session(), Category::Transfer, Severity::Info, "TRANSFER", "skipped");
        assert_eq!(fs::read_to_string(directory.join(COMBINED_FILE)).unwrap().lines().count(), 2);
        let _ = fs::remove_dir_all(&directory);
    }
}
