# Rust SFTP Client

A native Rust desktop SFTP client with an information-dense, analyst-workstation interface inspired by the Tiramisu-TL WebUI. The application is rendered directly with egui; it does not embed a web frontend.

> **Status:** Early development. The native desktop shell and local filesystem pane are implemented. The Rust core contains validated connection-profile types, a tested segmented-download planner, and a streaming range-download engine. The desktop connection/profile/remote-browser workflow is still being integrated.

## Technology

- **eframe + egui** for the native Rust desktop interface.
- **Tokio** for asynchronous networking and transfer orchestration.
- **russh 0.63.x** for SSH transport and authentication.
- **russh-sftp 3.0.1** for SFTP v3.
- **serde** for profile and transfer-state serialization.

There is no Tauri, React, TypeScript, Vite, Node.js, or NPM build step.

## Build

Run these commands from the repository root:

```bash
cargo run --release
```

Build an optimized binary without launching it:

```bash
cargo build --release
```

The executable is written to `target/release/rust-sftp-client`.

## Interface

- Dense dual-pane local/remote workspace.
- Compact file rows with size, modification time, and type.
- Local filesystem navigation, parent navigation, and filtering.
- Persistent session/navigation sidebar.
- Transfer activity panel and connection status.
- Connection profile form and segmented-transfer settings.

## Segmented downloads

The transfer core now includes a streaming SFTP range-download engine:

1. Reads remote file metadata and obtains its size.
2. Uses the existing range planner to split large files into contiguous, non-overlapping byte ranges.
3. Opens an independent SFTP file handle for each range and seeks to its starting offset.
4. Streams each range to a separate temporary part file using a bounded memory buffer.
5. Retries failed ranges up to three times.
6. Assembles completed parts in byte order, flushes the output, checks the final byte count, and renames the completed file into place.
7. Emits byte and segment progress through a Tokio unbounded channel.

Files below the configured threshold use a single range. Zero-byte files are handled without issuing a range read. A failed segment prevents finalization, so an incomplete download is never presented as a completed destination file.

The engine is exposed as `transfer::download_file`; the desktop queue still needs to invoke it and render its progress events. Persistent cross-process resume and parallel independent SSH sessions are not implemented yet; segments currently share one authenticated SFTP session while using separate SFTP file handles.

## Initial defaults

| Setting | Default |
|---|---:|
| Segmentation threshold | 64 MiB |
| Concurrent segments per file | 8 |
| Target segment size | 8 MiB |
| Maximum concurrent transfers | 4 |
| Segment retry attempts | 3 |

## Security

- Never store plaintext passwords in connection profiles.
- Verify SSH host keys and make trust changes explicit; changed keys must never be silently accepted.
- Keep private-key material out of logs and UI state.
- Use restrictive permissions for temporary transfer state and partial files.
- Treat remote filenames and server-provided metadata as untrusted input.

See `docs/architecture.md` and `docs/transfer-engine.md` for implementation constraints.
