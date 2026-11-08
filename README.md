# Rust SFTP Client

A native Rust desktop SFTP client with an information-dense, analyst-workstation interface inspired by the Tiramisu-TL WebUI. The application is rendered directly with eframe/egui; it does not embed a web frontend.

> **Status:** The native dual-pane UI, local and remote filesystem browsing, password and private-key SSH authentication, explicit SSH host-key pinning, segmented downloads, and recursive drag-and-drop transfers are integrated. SSH-agent authentication and transfer cancellation are not implemented yet. Build and runtime verification are still required on the target system.

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

## Implemented workflows

- Save and load non-secret connection profiles.
- Authenticate with SSH passwords or an unencrypted private-key file.
- Verify server keys using SHA-256 fingerprints. Unknown keys are rejected until explicitly trusted; a changed pinned key is rejected and cannot be silently replaced.
- Store trusted fingerprints in `~/.config/rust-sftp-client/known_hosts.json`.
- Browse remote directories, navigate into directories and to the parent, and filter remote entries.
- Select multiple remote files with Ctrl/Command-click and download them into the current local pane directory.
- Drag local files or folders onto the remote pane to upload them recursively; each discovered file appears as its own transfer row.
- Drag remote files or folders onto the local pane to download them recursively; each discovered file appears as its own transfer row and large files retain segmented downloads.
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
