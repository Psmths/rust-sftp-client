//! Saved passwords, kept in the operating system's credential store:
//! Windows Credential Manager, the Secret Service (GNOME Keyring, KWallet,
//! KeePassXC, …) on Linux, or the Keychain on macOS. Passwords are never
//! written to the profiles file.
//!
//! Store access can block (e.g. while the user unlocks their keyring), so the
//! app calls these functions from background threads.

use crate::connection::ConnectionProfile;

const SERVICE: &str = "rust-sftp-client";

/// Credential-store account name for a profile's server login. Profiles that
/// log in to the same account share one saved password.
pub fn key(profile: &ConnectionProfile) -> String {
    format!("{}@{}:{}", profile.username, profile.host, profile.port)
}

/// The saved password, or `None` if there is none.
pub fn load(key: &str) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(SERVICE, key).map_err(describe)?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(describe(error)),
    }
}

pub fn store(key: &str, password: &str) -> Result<(), String> {
    keyring::Entry::new(SERVICE, key)
        .and_then(|entry| entry.set_password(password))
        .map_err(describe)
}

/// Removes a saved password; succeeds if there was none.
pub fn delete(key: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, key).map_err(describe)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(describe(error)),
    }
}

fn describe(error: keyring::Error) -> String {
    match error {
        keyring::Error::NoDefaultStore => {
            "no system credential store is available (on Linux, a Secret Service such as GNOME Keyring or KWallet must be running)".into()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::AuthMethod;

    #[test]
    fn key_identifies_the_server_login() {
        let profile = ConnectionProfile {
            name: "Lab".into(),
            host: "sftp.example.test".into(),
            port: 2222,
            username: "analyst".into(),
            auth_method: AuthMethod::Password,
            private_key_path: None,
            save_password: true,
        };
        assert_eq!(key(&profile), "analyst@sftp.example.test:2222");
    }
}
