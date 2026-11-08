# Rust SFTP Client

A native Rust desktop SFTP client with an information-dense, analyst-workstation interface inspired by the Tiramisu-TL WebUI. The application is rendered directly with eframe/egui; it does not embed a web frontend.

> **Status:** The native dual-pane UI, local and remote filesystem browsing, password and private-key SSH authentication, explicit SSH host-key pinning, segmented downloads, and recursive drag-and-drop transfers are integrated. SSH-agent authentication is not implemented yet. Build and runtime verification are still required on the target system.

## Technology

- **eframe + egui** for the native desktop interface.
- **Tokio** for asynchronous networking and transfer orchestration.
- **russh 0.63.x** for SSH transport and authentication.
- **russh-sftp 3.0.1** for SFTP v3.
- **serde** for profile and transfer-state serialization.

There is no Tauri, React, TypeScript, Vite, Node.js, or NPM build step.

## Build

```bash
cargo test
cargo build --release
```

The executable is written to `target/release/rust-sftp-client`.

Every push to `main` is built and tested on Linux and Windows by GitHub Actions
([.github/workflows/build.yml](.github/workflows/build.yml)). The binaries are attached to each
run as artifacts (`rust-sftp-client-linux-x86_64.tar.gz` and `rust-sftp-client-windows-x86_64.exe`)
and kept for 30 days. A build can also be started by hand from the Actions tab.

When both builds succeed on a push to `main`, a GitHub Release is published automatically,
tagged `v<Cargo.toml version>-build.<run number>` (e.g. `v0.1.0-build.42`), with both binaries,
a `SHA256SUMS.txt` file and notes listing the changes since the previous release. Manual runs
only build.

## Faster downloads with rsftp-turbo (optional)

`rsftp-turbo` is a small server-side helper that downloads files over UDP instead of SFTP, avoiding
SFTP's per-request round trips. Browsing, uploads and logins still use SSH/SFTP, and downloads fall
back to SFTP automatically when the server has no helper or UDP is blocked.

* Install on the server from the `rsftp-turbo-linux-x86_64.tar.gz` release asset (`sudo ./install.sh`)
  and open UDP port 6767. See [crates/turbo-server/dist/README.md](crates/turbo-server/dist/README.md).
* Each download is authorised over the SSH session (`rsftp-turbo ticket` runs as the logged-in user,
  so only files that user can read are offered), every UDP packet is encrypted and authenticated with
  AES-256-GCM, lost packets are re-requested, and every segment is verified against an XXH3-128 digest
  computed on the server and downloaded again if it does not match.
* Downloads keep their progress in a hidden `.<name>.rsftp-part` file: if turbo fails part-way, SFTP
  finishes only the missing pieces, and an interrupted download resumes where it stopped (when the
  remote file is unchanged). Stopping a transfer deletes its partial file.
* Toggle it under *Settings → Network Settings → UDP downloads*. The log records which protocol was used.

## Troubleshooting startup

The Windows build draws with Direct3D 12 (via wgpu), which also works in virtual machines without GPU
drivers; Linux uses OpenGL. If the preferred renderer fails, the app restarts itself once with the other
one. If both fail, an error dialog explains why and the details are appended to
`startup-error.log` in the config folder (`~/.config/rust-sftp-client/` or
`%USERPROFILE%\.config\rust-sftp-client\`). A renderer can be forced with the
`RUST_SFTP_CLIENT_RENDERER` environment variable (`wgpu` or `glow`).

## Implemented workflows

- Save and load non-secret connection profiles.
- Authenticate with SSH passwords or an unencrypted private-key file.
- Verify server keys using SHA-256 fingerprints. Unknown keys are rejected until explicitly trusted; a changed pinned key is rejected and cannot be silently replaced.
- Optionally save passwords per login (user, host and port) in the system credential store: Windows Credential Manager, or a Secret Service keyring such as GNOME Keyring or KWallet on Linux. Passwords are never written to the profiles file; a password is saved only after it has logged in successfully or when a profile is saved with one entered.
- Store trusted fingerprints in `~/.config/rust-sftp-client/known_hosts.json`.
- Browse remote directories, navigate into directories and to the parent, and filter remote entries.
- Select multiple remote files with Ctrl/Command-click and download them into the current local pane directory.
- Drag local files or folders onto the remote pane to upload them recursively; each discovered file appears as its own transfer row.
- Drag remote files or folders onto the local pane to download them recursively; each discovered file appears as its own transfer row and large files retain segmented downloads.
- Stop a single transfer (or a whole folder transfer) or all transfers from the transfer queue's right-click menu. Stopped transfers clean up after themselves: partial downloads' temporary files and partially uploaded remote files are removed.
- Show per-file queued, active, completed, and failed transfers with independent byte progress, elapsed time, and ETA.
- Download large files through the existing bounded, retrying segmented range-download engine.
- Open connection, password, host-key trust, error, and transfer-settings prompts in separate native windows.

## Segmented downloads

1. Read remote metadata and obtain the file size.
2. Split large files into contiguous, non-overlapping byte ranges.
3. Open an independent SFTP file handle for each range and seek to its starting offset.
4. Create one pre-sized temporary output file.
5. Stream each range directly to its assigned byte offsets using positional writes (Unix `write_at`, Windows `seek_write`) and a bounded memory buffer.
6. Retry failed ranges up to three times; retries overwrite only that segment's byte range.
7. Wait for all workers to stop, flush the output, validate its size, and rename it into place.
8. Emit byte and segment progress to the desktop transfer queue.

All segments share one authenticated SFTP session and use independent SFTP file handles. Persistent cross-process resume and parallel independent SSH sessions are not implemented.

## Initial transfer defaults

| Setting | Default |
|---|---:|
| Segmentation threshold | 64 MiB |
| Target segment size | 8 MiB |
| Maximum segments per file | 8 |
| Maximum concurrent transfers | 4 |
| Segment retry attempts | 3 |

## Security notes

- Passwords are not persisted in connection profiles.
- Unknown SSH host keys require an explicit trust action.
- Changed host keys are rejected; the existing pin is not overwritten.
- Private-key contents and passwords are not written to profile storage.

The trust-store file should be protected by the local user's filesystem permissions. Encrypted private-key passphrases, OS keychain integration, SSH-agent authentication, upload, and transfer cancellation remain future work.
