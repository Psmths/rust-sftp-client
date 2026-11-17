//! Network tuning applied when a connection is opened.

use std::{borrow::Cow, time::Duration};

use russh::{cipher, compression};
use serde::{Deserialize, Serialize};

/// Which AEAD cipher family to offer first. Superseded by
/// [`SshAlgorithms::ciphers`]; still read from older settings files so a
/// ChaCha20 choice carries over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CipherPreference {
    /// AES-GCM: fastest on CPUs with AES instructions (practically all
    /// x86-64 and ARMv8 machines).
    AesGcm,
    /// ChaCha20-Poly1305: faster on CPUs without AES acceleration.
    ChaCha20,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NetworkSettings {
    /// SFTP channels opened on each SSH connection. Transfers are spread over
    /// them, so each gets its own SSH flow-control window.
    pub sftp_channels: u32,
    /// SFTP read/write requests kept in flight per open file.
    pub pipelined_requests: u32,
    /// Largest SFTP packet in KiB, used for both reads and writes. Servers
    /// that announce smaller limits (`limits@openssh.com`) are respected.
    pub sftp_packet_kib: u32,
    /// SSH channel receive window in MiB: data the server may send before
    /// waiting for an acknowledgement. Raise for high-latency links.
    pub ssh_window_mib: u32,
    /// Legacy cipher choice; only used when `algorithms` is not set.
    #[serde(skip_serializing)]
    pub cipher: CipherPreference,
    /// Key exchange, cipher, MAC and host-key algorithms offered, in order.
    /// `None` in settings files from before this option existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<SshAlgorithms>,
    /// Offer zlib compression. Helps on slow links with compressible data,
    /// costs CPU and slows fast links.
    pub compression: bool,
    /// Seconds between SSH keepalives; 0 disables them.
    pub keepalive_secs: u32,
    /// Seconds to wait for a single SFTP request before failing it.
    pub request_timeout_secs: u32,
    /// Files transferred at the same time on one connection, from folder
    /// transfers and individual file transfers alike.
    pub parallel_files: u32,
    /// Download over rsftp-turbo (UDP) when the server offers it.
    pub turbo: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            sftp_channels: 4,
            pipelined_requests: 64,
            sftp_packet_kib: 256,
            ssh_window_mib: 16,
            cipher: CipherPreference::AesGcm,
            algorithms: None,
            compression: false,
            keepalive_secs: 30,
            request_timeout_secs: 30,
            parallel_files: 4,
            turbo: true,
        }
    }
}

/// Largest SSH packet we accept from the server (the protocol's practical maximum).
const SSH_MAX_PACKET: u32 = 65_535;

impl NetworkSettings {
    pub fn ssh_config(&self) -> russh::client::Config {
        let window = self.ssh_window_mib.clamp(1, 1024).saturating_mul(1024 * 1024);
        let algorithms = self.algorithms();
        let compressions = if self.compression {
            vec![compression::ZLIB_LEGACY, compression::ZLIB, compression::NONE]
        } else {
            vec![compression::NONE]
        };
        let mut config = russh::client::Config::default();
        config.nodelay = true;
        config.window_size = window;
        config.maximum_packet_size = SSH_MAX_PACKET;
        // Enough queued channel messages to hold a full window of packets,
        // so a large window is not throttled by the internal queue.
        config.channel_buffer_size = (window / 32_768).clamp(100, 4096) as usize;
        config.keepalive_interval = (self.keepalive_secs > 0).then(|| Duration::from_secs(self.keepalive_secs.into()));
        config.preferred = algorithms.preferred(compressions);
        config
    }

    /// The algorithm lists in effect (from older settings: the defaults,
    /// with the legacy cipher choice first).
    pub fn algorithms(&self) -> SshAlgorithms {
        match &self.algorithms {
            Some(algorithms) => algorithms.clone().normalized(),
            None => SshAlgorithms::from_legacy(self.cipher),
        }
    }

    pub fn sftp_config(&self) -> russh_sftp::client::Config {
        let packet = self.sftp_packet_kib.clamp(32, 256) * 1024;
        let pipelined = self.pipelined_requests.clamp(1, 256) as usize;
        russh_sftp::client::Config {
            max_packet_len: packet,
            max_concurrent_reads: pipelined,
            max_concurrent_writes: pipelined,
            max_write_packet_len: packet,
            request_timeout_secs: self.request_timeout_secs.clamp(1, 3600).into(),
        }
    }

    pub fn channel_count(&self) -> usize {
        self.sftp_channels.clamp(1, 16) as usize
    }

    pub fn file_parallelism(&self) -> usize {
        self.parallel_files.clamp(1, 32) as usize
    }
}

/// The four kinds of algorithm negotiated when an SSH connection starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AlgorithmKind {
    #[default]
    KeyExchange,
    Cipher,
    Mac,
    HostKey,
}

/// An algorithm this client implements.
pub struct KnownAlgorithm {
    pub name: &'static str,
    /// Offered unless the user turns it off. Weak algorithms are off by default.
    pub weak: bool,
}

const fn known(name: &'static str) -> KnownAlgorithm {
    KnownAlgorithm { name, weak: false }
}

const fn weak(name: &'static str) -> KnownAlgorithm {
    KnownAlgorithm { name, weak: true }
}

/// Every key exchange method, in the default order.
const KEY_EXCHANGES: &[KnownAlgorithm] = &[
    known("mlkem768x25519-sha256"),
    known("curve25519-sha256"),
    known("curve25519-sha256@libssh.org"),
    known("ecdh-sha2-nistp256"),
    known("ecdh-sha2-nistp384"),
    known("ecdh-sha2-nistp521"),
    known("diffie-hellman-group-exchange-sha256"),
    known("diffie-hellman-group18-sha512"),
    known("diffie-hellman-group17-sha512"),
    known("diffie-hellman-group16-sha512"),
    known("diffie-hellman-group15-sha512"),
    known("diffie-hellman-group14-sha256"),
    weak("diffie-hellman-group-exchange-sha1"),
    weak("diffie-hellman-group14-sha1"),
    weak("diffie-hellman-group1-sha1"),
];

/// Every cipher, in the default order: AES-GCM first, as it is the fastest
/// on CPUs with AES instructions.
const CIPHERS: &[KnownAlgorithm] = &[
    known("aes128-gcm@openssh.com"),
    known("aes256-gcm@openssh.com"),
    known("chacha20-poly1305@openssh.com"),
    known("aes128-ctr"),
    known("aes192-ctr"),
    known("aes256-ctr"),
    weak("aes128-cbc"),
    weak("aes192-cbc"),
    weak("aes256-cbc"),
];

/// Every MAC (used only with ciphers that are not AEAD: CTR and CBC).
const MACS: &[KnownAlgorithm] = &[
    known("hmac-sha2-256-etm@openssh.com"),
    known("hmac-sha2-512-etm@openssh.com"),
    known("hmac-sha2-256"),
    known("hmac-sha2-512"),
    weak("hmac-sha1-etm@openssh.com"),
    weak("hmac-sha1"),
];

/// Every server host-key algorithm.
const HOST_KEYS: &[KnownAlgorithm] = &[
    known("ssh-ed25519"),
    known("ecdsa-sha2-nistp256"),
    known("ecdsa-sha2-nistp384"),
    known("ecdsa-sha2-nistp521"),
    known("rsa-sha2-512"),
    known("rsa-sha2-256"),
    weak("ssh-rsa"),
];

impl AlgorithmKind {
    pub const ALL: [AlgorithmKind; 4] =
        [AlgorithmKind::KeyExchange, AlgorithmKind::Cipher, AlgorithmKind::Mac, AlgorithmKind::HostKey];

    pub fn label(self) -> &'static str {
        match self {
            AlgorithmKind::KeyExchange => "Key exchange",
            AlgorithmKind::Cipher => "Ciphers",
            AlgorithmKind::Mac => "MACs",
            AlgorithmKind::HostKey => "Host keys",
        }
    }

    pub fn known(self) -> &'static [KnownAlgorithm] {
        match self {
            AlgorithmKind::KeyExchange => KEY_EXCHANGES,
            AlgorithmKind::Cipher => CIPHERS,
            AlgorithmKind::Mac => MACS,
            AlgorithmKind::HostKey => HOST_KEYS,
        }
    }

    pub fn is_weak(self, name: &str) -> bool {
        self.known().iter().any(|algorithm| algorithm.name == name && algorithm.weak)
    }

    /// The default list: every algorithm in order, the weak ones turned off.
    pub fn defaults(self) -> Vec<AlgorithmChoice> {
        self.known().iter().map(|algorithm| AlgorithmChoice { name: algorithm.name.into(), enabled: !algorithm.weak }).collect()
    }
}

/// One algorithm in a preference list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmChoice {
    pub name: String,
    pub enabled: bool,
}

/// The algorithms offered to the server, most preferred first. The server
/// picks the first entry of each list that it also supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SshAlgorithms {
    pub key_exchange: Vec<AlgorithmChoice>,
    pub ciphers: Vec<AlgorithmChoice>,
    pub macs: Vec<AlgorithmChoice>,
    pub host_keys: Vec<AlgorithmChoice>,
}

impl Default for SshAlgorithms {
    fn default() -> Self {
        Self {
            key_exchange: AlgorithmKind::KeyExchange.defaults(),
            ciphers: AlgorithmKind::Cipher.defaults(),
            macs: AlgorithmKind::Mac.defaults(),
            host_keys: AlgorithmKind::HostKey.defaults(),
        }
    }
}

impl SshAlgorithms {
    /// Defaults with the cipher family chosen in older settings files first.
    pub fn from_legacy(cipher: CipherPreference) -> Self {
        let mut algorithms = Self::default();
        if cipher == CipherPreference::ChaCha20 {
            let list = &mut algorithms.ciphers;
            if let Some(index) = list.iter().position(|choice| choice.name == "chacha20-poly1305@openssh.com") {
                let chacha = list.remove(index);
                list.insert(0, chacha);
            }
        }
        algorithms
    }

    pub fn list(&self, kind: AlgorithmKind) -> &Vec<AlgorithmChoice> {
        match kind {
            AlgorithmKind::KeyExchange => &self.key_exchange,
            AlgorithmKind::Cipher => &self.ciphers,
            AlgorithmKind::Mac => &self.macs,
            AlgorithmKind::HostKey => &self.host_keys,
        }
    }

    pub fn list_mut(&mut self, kind: AlgorithmKind) -> &mut Vec<AlgorithmChoice> {
        match kind {
            AlgorithmKind::KeyExchange => &mut self.key_exchange,
            AlgorithmKind::Cipher => &mut self.ciphers,
            AlgorithmKind::Mac => &mut self.macs,
            AlgorithmKind::HostKey => &mut self.host_keys,
        }
    }

    /// Drops unknown and repeated names and appends algorithms missing from
    /// the lists (with their default state), so every list holds each known
    /// algorithm exactly once.
    pub fn normalized(mut self) -> Self {
        for kind in AlgorithmKind::ALL {
            let list = self.list_mut(kind);
            let mut seen = std::collections::HashSet::new();
            list.retain(|choice| kind.known().iter().any(|known| known.name == choice.name) && seen.insert(choice.name.clone()));
            for default in kind.defaults() {
                if !list.iter().any(|choice| choice.name == default.name) {
                    list.push(default);
                }
            }
        }
        self
    }

    /// The first kind of algorithm with nothing turned on, if any.
    pub fn empty_kind(&self) -> Option<AlgorithmKind> {
        AlgorithmKind::ALL.into_iter().find(|&kind| !self.list(kind).iter().any(|choice| choice.enabled))
    }

    fn enabled(&self, kind: AlgorithmKind) -> impl Iterator<Item = &str> {
        self.list(kind).iter().filter(|choice| choice.enabled).map(|choice| choice.name.as_str())
    }

    fn preferred(&self, compression: Vec<compression::Name>) -> russh::Preferred {
        use russh::{kex, keys::Algorithm, mac};
        let defaults = russh::Preferred::default();
        let mut kex: Vec<kex::Name> = self.enabled(AlgorithmKind::KeyExchange).filter_map(|name| kex::Name::try_from(name).ok()).collect();
        // Protocol extensions (ext-info, strict key exchange against the
        // Terrapin attack) travel in the key exchange list; always offer them.
        kex.extend([kex::EXTENSION_SUPPORT_AS_CLIENT, kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT]);
        let ciphers: Vec<cipher::Name> = self.enabled(AlgorithmKind::Cipher).filter_map(|name| cipher::Name::try_from(name).ok()).collect();
        let macs: Vec<mac::Name> = self.enabled(AlgorithmKind::Mac).filter_map(|name| mac::Name::try_from(name).ok()).collect();
        let keys: Vec<Algorithm> = self.enabled(AlgorithmKind::HostKey).filter_map(|name| Algorithm::new(name).ok()).collect();
        russh::Preferred {
            kex: if kex.len() > 2 { Cow::Owned(kex) } else { defaults.kex },
            key: if keys.is_empty() { defaults.key } else { Cow::Owned(keys) },
            cipher: if ciphers.is_empty() { defaults.cipher } else { Cow::Owned(ciphers) },
            mac: if macs.is_empty() { defaults.mac } else { Cow::Owned(macs) },
            compression: Cow::Owned(compression),
            host_key_certificates: defaults.host_key_certificates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_raise_throughput_limits() {
        let settings = NetworkSettings::default();
        let ssh = settings.ssh_config();
        assert_eq!(ssh.window_size, 16 * 1024 * 1024);
        assert!(ssh.nodelay);
        assert_eq!(ssh.preferred.cipher[0], cipher::AES_128_GCM);
        // Weak algorithms are not offered by default.
        assert!(!ssh.preferred.cipher.contains(&cipher::AES_128_CBC));
        assert!(!ssh.preferred.mac.iter().any(|mac| mac.as_ref().contains("sha1")));
        assert!(!ssh.preferred.kex.iter().any(|kex| kex.as_ref().ends_with("sha1")));
        assert_eq!(&*ssh.preferred.compression, &[compression::NONE]);
        let sftp = settings.sftp_config();
        assert_eq!(sftp.max_packet_len, 256 * 1024);
        assert_eq!(sftp.max_write_packet_len, 256 * 1024);
        assert_eq!(sftp.max_concurrent_reads, 64);
    }

    #[test]
    fn every_known_algorithm_is_implemented() {
        use russh::{kex, keys::Algorithm, mac};
        for algorithm in KEY_EXCHANGES {
            assert!(kex::Name::try_from(algorithm.name).is_ok(), "{}", algorithm.name);
        }
        for algorithm in CIPHERS {
            assert!(cipher::Name::try_from(algorithm.name).is_ok(), "{}", algorithm.name);
        }
        for algorithm in MACS {
            assert!(mac::Name::try_from(algorithm.name).is_ok(), "{}", algorithm.name);
        }
        for algorithm in HOST_KEYS {
            assert!(Algorithm::new(algorithm.name).is_ok(), "{}", algorithm.name);
        }
    }

    #[test]
    fn legacy_chacha_choice_is_kept() {
        let settings = NetworkSettings { cipher: CipherPreference::ChaCha20, ..Default::default() };
        assert_eq!(settings.ssh_config().preferred.cipher[0], cipher::CHACHA20_POLY1305);
        let old: NetworkSettings = serde_json::from_str(r#"{"cipher":"chaCha20"}"#).unwrap();
        assert_eq!(old.ssh_config().preferred.cipher[0], cipher::CHACHA20_POLY1305);
    }

    #[test]
    fn custom_order_and_choices_are_offered() {
        let mut algorithms = SshAlgorithms::default();
        algorithms.ciphers.retain(|choice| choice.name == "aes256-ctr");
        algorithms.macs.reverse();
        let settings = NetworkSettings { algorithms: Some(algorithms), ..Default::default() };
        let preferred = settings.ssh_config().preferred;
        // Missing ciphers come back, but turned on only if they are not weak.
        assert_eq!(preferred.cipher[0], cipher::AES_256_CTR);
        assert!(!preferred.cipher.contains(&cipher::AES_256_CBC));
        assert_eq!(preferred.mac[0], russh::mac::HMAC_SHA512);
        assert!(preferred.kex.contains(&russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT));
    }

    #[test]
    fn normalizing_drops_unknown_and_repeated_names() {
        let mut algorithms = SshAlgorithms::default();
        algorithms.ciphers.insert(0, AlgorithmChoice { name: "rot13".into(), enabled: true });
        algorithms.ciphers.push(algorithms.ciphers[1].clone());
        assert_eq!(algorithms.normalized(), SshAlgorithms::default());
    }

    #[test]
    fn out_of_range_values_are_clamped() {
        let settings = NetworkSettings { sftp_packet_kib: 4, pipelined_requests: 0, sftp_channels: 99, ..Default::default() };
        assert_eq!(settings.sftp_config().max_packet_len, 32 * 1024);
        assert_eq!(settings.sftp_config().max_concurrent_reads, 1);
        assert_eq!(settings.channel_count(), 16);
    }
}
