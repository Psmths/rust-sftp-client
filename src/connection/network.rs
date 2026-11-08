//! Network tuning applied when a connection is opened.

use std::{borrow::Cow, time::Duration};

use russh::{cipher, compression};
use serde::{Deserialize, Serialize};

/// Which AEAD cipher family to offer first. The server picks the first entry
/// in our list that it also supports, so this decides the bulk cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CipherPreference {
    /// AES-GCM: fastest on CPUs with AES instructions (practically all
    /// x86-64 and ARMv8 machines).
    AesGcm,
    /// ChaCha20-Poly1305: faster on CPUs without AES acceleration.
    ChaCha20,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub cipher: CipherPreference,
    /// Offer zlib compression. Helps on slow links with compressible data,
    /// costs CPU and slows fast links.
    pub compression: bool,
    /// Seconds between SSH keepalives; 0 disables them.
    pub keepalive_secs: u32,
    /// Seconds to wait for a single SFTP request before failing it.
    pub request_timeout_secs: u32,
    /// Files transferred at the same time within one folder transfer.
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
        let ciphers = match self.cipher {
            CipherPreference::AesGcm => vec![
                cipher::AES_128_GCM,
                cipher::AES_256_GCM,
                cipher::CHACHA20_POLY1305,
                cipher::AES_128_CTR,
                cipher::AES_256_CTR,
            ],
            CipherPreference::ChaCha20 => vec![
                cipher::CHACHA20_POLY1305,
                cipher::AES_128_GCM,
                cipher::AES_256_GCM,
                cipher::AES_128_CTR,
                cipher::AES_256_CTR,
            ],
        };
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
        config.preferred = russh::Preferred {
            cipher: Cow::Owned(ciphers),
            compression: Cow::Owned(compressions),
            ..Default::default()
        };
        config
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
        assert_eq!(&*ssh.preferred.compression, &[compression::NONE]);
        let sftp = settings.sftp_config();
        assert_eq!(sftp.max_packet_len, 256 * 1024);
        assert_eq!(sftp.max_write_packet_len, 256 * 1024);
        assert_eq!(sftp.max_concurrent_reads, 64);
    }

    #[test]
    fn out_of_range_values_are_clamped() {
        let settings = NetworkSettings { sftp_packet_kib: 4, pipelined_requests: 0, sftp_channels: 99, ..Default::default() };
        assert_eq!(settings.sftp_config().max_packet_len, 32 * 1024);
        assert_eq!(settings.sftp_config().max_concurrent_reads, 1);
        assert_eq!(settings.channel_count(), 16);
    }
}
