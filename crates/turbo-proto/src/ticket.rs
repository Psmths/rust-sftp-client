//! The ticket `rsftp-turbo ticket` prints on the server and the client reads
//! back over SSH. It contains the transfer key, so it must only ever travel
//! over the encrypted SSH channel.

use serde::{Deserialize, Serialize};

use crate::wire::KEY_LEN;

pub const PROTOCOL_VERSION: u32 = 1;
/// Command the client runs over SSH; the file path is written to its stdin.
pub const TICKET_COMMAND: &str = "rsftp-turbo ticket";
/// Long-lived variant: one request per line on stdin, one [`StreamReply`]
/// JSON line per request on stdout. The client keeps it running for the whole
/// SSH connection, so it needs only one SSH channel however many files it
/// fetches. A request is either a file path (ticket request) or, if the line
/// starts with `{`, a JSON [`StreamRequest`]. Ticket requests are always
/// absolute paths, so the two never collide.
pub const TICKET_STREAM_COMMAND: &str = "rsftp-turbo ticket --stream";

/// A JSON request line of `rsftp-turbo ticket --stream`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRequest {
    /// Directory to list: absolute, or relative to the login's home folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
}

/// One line of `rsftp-turbo ticket --stream` output.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamReply {
    #[serde(default)]
    pub ticket: Option<Ticket>,
    #[serde(default)]
    pub error: Option<String>,
    /// The error means the service itself is unusable (not just this file).
    #[serde(default)]
    pub service_unavailable: bool,
    /// Answer to a list request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing: Option<Listing>,
    /// Set on every answer to a list request, failed ones included. A helper
    /// too old to list reads the request as a file name and answers without it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub list_reply: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A directory as the logged-in user sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// Absolute path with symbolic links resolved (like SFTP `realpath`).
    pub path: String,
    /// Every entry except `.` and `..`, unsorted.
    pub entries: Vec<ListEntry>,
}

/// One directory entry. Like an SFTP listing, symbolic links are described
/// themselves, not their targets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEntry {
    pub name: String,
    #[serde(default)]
    pub dir: bool,
    #[serde(default)]
    pub size: u64,
    /// Modification time, Unix seconds.
    #[serde(default)]
    pub mtime: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub version: u32,
    pub transfer: u64,
    /// AES-256 key, hex encoded.
    pub key: String,
    pub port: u16,
    /// The server's own address from `SSH_CONNECTION`. Behind NAT this is a
    /// private address, so clients prefer the host they connected to and only
    /// fall back to this one.
    #[serde(default)]
    pub address: Option<String>,
    /// File size when the ticket was issued.
    pub size: u64,
}

impl Ticket {
    pub fn key_bytes(&self) -> Option<[u8; KEY_LEN]> {
        let bytes = from_hex(&self.key)?;
        bytes.try_into().ok()
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    let digit = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("abc"), None);
    }

    #[test]
    fn ticket_parses_and_exposes_the_key() {
        let json = format!(
            r#"{{"version":1,"transfer":42,"key":"{}","port":6767,"address":"192.0.2.1","size":10}}"#,
            to_hex(&[3_u8; KEY_LEN])
        );
        let ticket: Ticket = serde_json::from_str(&json).unwrap();
        assert_eq!(ticket.key_bytes(), Some([3_u8; KEY_LEN]));
        let short = Ticket { key: "00".into(), ..ticket };
        assert_eq!(short.key_bytes(), None);
    }

    #[test]
    fn list_replies_round_trip_and_old_replies_still_parse() {
        let reply = StreamReply {
            listing: Some(Listing {
                path: "/home/u".into(),
                entries: vec![ListEntry { name: "a".into(), dir: true, size: 0, mtime: Some(5) }],
            }),
            list_reply: true,
            ..StreamReply::default()
        };
        let json = serde_json::to_string(&reply).unwrap();
        assert_eq!(serde_json::from_str::<StreamReply>(&json).unwrap(), reply);

        // A pre-listing helper's answer to a list request: a plain file error.
        let old: StreamReply = serde_json::from_str(r#"{"ticket":null,"error":"cannot open","service_unavailable":false}"#).unwrap();
        assert!(!old.list_reply && old.listing.is_none());

        // Ticket replies do not grow new fields.
        let plain = serde_json::to_string(&StreamReply { error: Some("x".into()), ..StreamReply::default() }).unwrap();
        assert!(!plain.contains("list"));

        let request = serde_json::to_string(&StreamRequest { list: Some("/tmp".into()) }).unwrap();
        assert!(request.starts_with('{'));
    }
}
