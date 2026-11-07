# Rust SFTP Client

A cross-platform desktop SFTP client built with Rust and Tauri, with a dual-pane file manager and a transfer engine designed around resumable, parallel downloads.

> **Status:** Early project scaffold. The transfer engine and GUI are not implemented yet.

## Goals

- WinSCP-inspired dual-pane workflow: local files, remote files, and a transfer queue.
- SSH password, private-key, passphrase-protected key, and SSH-agent authentication.
- Saved connection profiles and verified host keys.
- Resumable uploads and downloads with clear progress and error reporting.
- Segmented downloads for large files, controlled by a user-configurable size threshold and concurrency limit.
- Conservative, measurable network tuning rather than arbitrary socket tweaks.

## Segmented download design

SFTP supports offset-based reads. The client can use these to divide a remote file into non-overlapping byte ranges and fetch those ranges concurrently over independent SFTP channels or sessions, subject to server limits.

The implementation must:

1. Read remote metadata and determine whether the file is eligible for segmentation.
2. Confirm that the server/session permits the required concurrent reads.
3. Divide the file into bounded ranges and schedule them with a configurable concurrency limit.
4. Write each range at its correct offset in a temporary destination file.
5. Retry failed ranges without corrupting completed ranges.
6. Persist enough transfer state to resume safely after interruption.
7. Verify final length and, when a trusted checksum is available, content integrity.
8. Rename the temporary file into place only after successful completion.

Parallel SFTP reads are not guaranteed to improve throughput on every server or network. The client must support falling back to a single stream and must avoid exceeding server connection/channel limits.

## Planned defaults

These are initial product defaults, not hard limits; expose them in Settings.

| Setting | Initial default |
|---|---:|
| Segmentation threshold | 64 MiB |
| Concurrent segments per file | 8 |
| Target segment size | 8 MiB |
| Maximum concurrent transfers | 4 |
| Retry attempts per segment | 3 |

## Technology direction

- Rust for the transfer engine and application services.
- Tauri 2 for the desktop shell.
- React + TypeScript for the interface.
- Tokio for asynchronous I/O and task scheduling.
- An actively maintained Rust SSH/SFTP implementation, selected after a protocol and maintenance review.

The SSH/SFTP library is intentionally not locked in until its algorithm support, host-key verification, agent support, SFTP protocol coverage, and concurrency behavior have been evaluated.

## Development

The repository is currently an architecture-first scaffold. See [docs/architecture.md](docs/architecture.md) and [docs/transfer-engine.md](docs/transfer-engine.md) for implementation constraints and milestones.

## Security principles

- Never store plaintext passwords.
- Use the operating system credential store for saved secrets.
- Verify SSH host keys and make trust changes explicit.
- Keep private-key material out of logs and frontend state.
- Use restrictive permissions for temporary transfer state and partial files.
- Treat remote filenames and server-provided metadata as untrusted input.
