# Rust SFTP Client

A native desktop SFTP client for Windows and Linux, written in Rust with egui, with a dual-pane
Windows Classic–style interface (light or dark).

## Features

- **Connections:** saved profiles, password or (unencrypted) private-key login, passwords optionally kept
  in the system credential store, SSH host keys pinned by SHA-256 fingerprint, one tab per connection,
  and a quick-connect menu next to the Connect button.
- **Browsing:** local and remote panes with sorting, Ctrl/Shift multi-select, filtering, recursive
  search, show/hide hidden items, new folder, rename and delete. The local pane reopens where you left off.
- **Transfers:** drag and drop or right-click to upload and download files and folders; large downloads
  are split into parallel segments and resume after interruptions. Failed transfers can be retried.
  When files exist already, a dialog lists them side by side and previews what Ignore / Overwrite /
  overwrite-if-different would do. Modification times are kept, so later transfers can compare them.
- **Queue panel:** Pending, Complete and Failed transfers (folder transfers expand to show their files;
  right-click to clear finished ones), the session's log, a statistics tab with a
  live speed graph, and an SSH Terminal tab with an interactive shell on the connected server (select
  text with the mouse; Ctrl+C copies a selection, or interrupts without one; Ctrl+V pastes).
- **Settings:** transfer and network tuning, SSH algorithms (key exchange, ciphers, MACs, host keys), SSH terminal options, logging to files, theme, and size units (binary, decimal,
  or speeds in bits).

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

Every push to `main` is built and tested on Linux and Windows by GitHub Actions, and a release
`v<version>-build.<run>` (e.g. `v0.4.5-build.42`) is published with both clients, the rsftp-turbo
package and `SHA256SUMS.txt`.

## Troubleshooting

- **The app does not start:** Windows draws with Direct3D 12, Linux with OpenGL; if one renderer fails the
  app retries with the other. Details go to `startup-error.log` in `~/.config/rust-sftp-client/`
  (`%USERPROFILE%\.config\rust-sftp-client\` on Windows). Force a renderer with
  `RUST_SFTP_CLIENT_RENDERER=wgpu` or `glow`.
- **What happened?** The Log tab of the queue panel shows every connection, listing, transfer and file
  operation of the session. Turn on *Settings → Logging* to also write them to files.
