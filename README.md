# Rust SFTP Client

A native Rust desktop SFTP client with an information-dense, analyst-workstation interface inspired by the Tiramisu-TL WebUI. The application is rendered directly with egui; it does not embed a web frontend.

> **Status:** Early development. The native desktop shell and local filesystem pane are implemented. SSH connection establishment, remote directory browsing, and transfer execution remain in progress. The Rust core contains validated connection-profile types and a tested segmented-download range planner.

## Technology

- **eframe + egui** for the native Rust desktop interface.
- **Tokio** for asynchronous networking and transfer orchestration.
- **russh 0.63.x** for SSH transport and authentication.
- **russh-sftp 3.0.1** for SFTP v3.
- **serde** for profile and transfer-state serialization.

There is no Tauri, React, TypeScript, Vite, Node.js, or NPM build step.

## Build

From the repository root:

```bash
cd src-tauri
cargo run --release
```

Build an optimized binary without launching it:

```bash
cd src-tauri
cargo build --release
```

The executable is written to `src-tauri/target/release/rust-sftp-client`.

## Interface

- Dense dual-pane local/remote workspace.
- Compact file rows with size, modification time, and type.
- Local filesystem navigation, parent navigation, and filtering.
- Persistent session/navigation sidebar.
- Transfer activity panel and connection status.
- Connection profile form and segmented-transfer settings.

## Segmented downloads

SFTP supports offset-based reads. The client can divide a remote file into non-overlapping byte ranges and fetch them concurrently over independent SFTP channels or sessions, subject to server limits.

The Rust core implements deterministic range planning. It produces contiguous half-open ranges, handles uneven file sizes without gaps or overlaps, respects a maximum segment count, and uses a single range below the configured threshold. Network workers, positional disk writes, retry logic, resume state, and finalization remain future work.

## Initial defaults

| Setting | Default |
|---|---:|
| Segmentation threshold | 64 MiB |
| Concurrent segments per file | 8 |
| Target segment size | 8 MiB |
| Maximum concurrent transfers | 4 |
| Retry attempts per segment | 3 |

## Security

- Never store plaintext passwords in connection profiles.
- Verify SSH host keys and make trust changes explicit; changed keys must never be silently accepted.
- Keep private-key material out of logs and UI state.
- Use restrictive permissions for temporary transfer state and partial files.
- Treat remote filenames and server-provided metadata as untrusted input.

See `docs/architecture.md` and `docs/transfer-engine.md` for implementation constraints.
