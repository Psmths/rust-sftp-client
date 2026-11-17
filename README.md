# Rust SFTP Client

A native desktop SFTP client for Windows and Linux, written in Rust with egui, with a dual-pane
Windows Classic–style interface (light or dark).

## Features

- **Connections:** saved profiles, password or (unencrypted) private-key login, passwords optionally kept
  in the system credential store, SSH host keys pinned by SHA-256 fingerprint, one tab per connection,
  and a quick-connect menu next to the Connect button.
- **Browsing:** local and remote panes with sorting, Ctrl/Shift multi-select, filtering, recursive
  search, show/hide hidden items, new folder, rename and delete. Bookmark folders with the star button and
  jump back to them from the Bookmarks drop-down (remote bookmarks are kept per server login). The local
  pane reopens where you left off.
- **Transfers:** drag and drop or right-click to upload and download files and folders; large downloads
  are split into parallel segments and resume after interruptions. Failed transfers can be retried.
  When files exist already, a dialog lists them side by side and previews what Ignore / Overwrite /
  overwrite-if-different would do. Modification times are kept, so later transfers can compare them.
- **Queue panel:** Pending, Complete and Failed transfers (folder transfers expand to show their files;
  right-click to clear finished ones), the session's log, a statistics tab with a
  live speed graph, and the SSH terminal.
- **Integrated SSH terminal:** an interactive shell on the connected server, opened over the same SSH
  connection as the file panes, with no second login. It runs full-screen programs such as `top`, `vim`
  and `htop`, keeps a scrollback history, and supports mouse selection (Ctrl+C copies a selection or
  interrupts without one; Ctrl+V pastes). Font size, colours, `TERM` type, scrollback length and copy
  behaviour can be changed in Settings.
- **Settings:** transfer and network tuning, SSH algorithms (key exchange, ciphers, MACs, host keys), terminal options, logging to files, theme, and size units (binary, decimal,
  or speeds in bits).

- **Automatic updates:** new versions are downloaded from this project's GitHub releases and installed
  in the background (the new version starts at the next launch, or right away after a restart). An update
  is installed only if its checksums carry the project's ed25519 release signature. Turn it off, or check
  by hand, in Settings › About, which also shows the version and where settings and logs are kept.

## Faster downloads with rsftp-turbo (optional)

`rsftp-turbo` is a small server helper that downloads files over UDP instead of SFTP and lists folders in
one round trip. Logins and permissions stay with SSH: the helper runs as the logged-in user, every UDP
packet is encrypted and authenticated (AES-256-GCM), and every segment is checked against a SHA-256
digest. Downloads fall back to SFTP automatically when the helper is missing or UDP is blocked.

Install it on the server from the `rsftp-turbo-<version>-linux-x86_64.tar.gz` release asset with
`sudo ./install.sh`, then open UDP port 6767. Details:
[crates/turbo-server/dist/README.md](crates/turbo-server/dist/README.md).

## Building

```bash
cargo test --workspace
cargo build --release          # target/release/rust-sftp-client
```