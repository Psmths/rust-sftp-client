//! Persistent application settings (`settings.json` next to the profiles).

use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{connection::NetworkSettings, logging::LoggingSettings, transfer::TransferSettings};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AppSettings {
    pub transfer: TransferSettings,
    pub network: NetworkSettings,
    pub logging: LoggingSettings,
    pub theme: crate::win32::Theme,
    /// Hide dot files (and, on Windows, files marked hidden) in both panes.
    pub hide_hidden_items: bool,
    /// Local folder shown when the app starts: the one last browsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_local_dir: Option<PathBuf>,
}

pub fn config_dir() -> Result<PathBuf, String> {
    let home = crate::places::home_dir().ok_or_else(|| "home directory is not set".to_owned())?;
    Ok(home.join(".config").join("rust-sftp-client"))
}

fn settings_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("settings.json"))
}

/// Missing or unreadable settings fall back to the defaults.
pub fn load() -> AppSettings {
    settings_path()
        .ok()
        .and_then(|path| fs::read(path).ok())
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

pub fn save(settings: &AppSettings) -> Result<(), String> {
    let path = settings_path()?;
    fs::create_dir_all(config_dir()?).map_err(|error| error.to_string())?;
    let data = serde_json::to_vec_pretty(settings).map_err(|error| error.to_string())?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, data).map_err(|error| error.to_string())?;
    fs::rename(&temp, &path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_settings_fill_in_defaults() {
        let parsed: AppSettings = serde_json::from_str(r#"{"logging":{"enabled":true}}"#).unwrap();
        assert!(parsed.logging.enabled);
        assert!(parsed.logging.log_connections);
        assert_eq!(parsed.transfer, TransferSettings::default());
        assert_eq!(parsed.network, NetworkSettings::default());
        assert_eq!(parsed.last_local_dir, None);
    }
}
