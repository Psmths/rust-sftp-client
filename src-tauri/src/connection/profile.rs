use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Authentication choice only. Secrets are deliberately not part of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthMethod {
    Password,
    PrivateKey,
    SshAgent,
}

/// A non-secret saved connection profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProfile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
}

impl ConnectionProfile {
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.name.trim().is_empty() { return Err(ProfileError::MissingName); }
        if self.host.trim().is_empty() { return Err(ProfileError::MissingHost); }
        if self.username.trim().is_empty() { return Err(ProfileError::MissingUsername); }
        if self.port == 0 { return Err(ProfileError::InvalidPort); }
        if self.auth_method == AuthMethod::PrivateKey
            && self.private_key_path.as_deref().map_or(true, |path| path.trim().is_empty())
        {
            return Err(ProfileError::MissingPrivateKeyPath);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("connection name is required")]
    MissingName,
    #[error("server hostname or address is required")]
    MissingHost,
    #[error("username is required")]
    MissingUsername,
    #[error("port must be between 1 and 65535")]
    InvalidPort,
    #[error("a private-key path is required for private-key authentication")]
    MissingPrivateKeyPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            name: "Lab".into(), host: "sftp.example.test".into(), port: 22,
            username: "analyst".into(), auth_method: AuthMethod::Password,
            private_key_path: None,
        }
    }

    #[test]
    fn accepts_valid_password_profile() { assert_eq!(profile().validate(), Ok(())); }

    #[test]
    fn rejects_empty_host() {
        let mut value = profile();
        value.host = "  ".into();
        assert_eq!(value.validate(), Err(ProfileError::MissingHost));
    }

    #[test]
    fn private_key_requires_a_path() {
        let mut value = profile();
        value.auth_method = AuthMethod::PrivateKey;
        assert_eq!(value.validate(), Err(ProfileError::MissingPrivateKeyPath));
    }

    #[test]
    fn serialized_profiles_have_no_credential_value_fields() {
        let serialized = serde_json::to_string(&profile()).expect("profile serializes");
        assert!(!serialized.contains("\"password\":"));
        assert!(!serialized.contains("\"passphrase\":"));
        assert!(!serialized.contains("\"privateKeyContents\":"));
    }
}
