# Rust SFTP Client

A cross-platform desktop SFTP client built with Rust and Tauri, with a WinSCP-inspired dual-pane file manager and a transfer engine designed around resumable, parallel downloads.

> **Status:** Early development. The UI is a scaffold; SSH connection and transfer operations are not wired up yet. The Rust core now contains validated connection-profile types and a tested segmented-download range planner.

## Goals

- WinSCP-inspired dual-pane workflow: local files, remote files, and a transfer queue.
- SSH password, private-key, passphrase-protected key, and SSH-agent authentication.
- Saved connection profiles and verified host keys.
- Resumable uploads and downloads with clear progress and error reporting.
- Segmented downloads for large files, controlled by a user-configurable size threshold and concurrency limit.
- Conservative, measurable network tuning rather than arbitrary socket tweaks.

## Segmented downloads

SFTP supports offset-based reads. The client can divide a remote file into non-overlapping byte ranges and fetch them concurrently over independent SFTP channels or sessions, subject to server limits.

The Rust core now implements deterministic range planning. It produces contiguous half-open ranges, handles uneven file sizes without gaps or overlaps, respects a maximum segment count, and uses a single range below the configured threshold. Network workers, positional disk writes, retry logic, resume state, and finalization remain future work.

Parallel SFTP reads are not guaranteed to improve throughput on every server or network. The client must support falling back to a single stream and must avoid exceeding server connection/channel limits.

## Initial defaults

| Setting | Default |
|---|---:|
| Segmentation threshold | 64 MiB |
| Concurrent segments per file | 8 |
| Target segment size | 8 MiB |
| Maximum concurrent transfers | 4 |
| Retry attempts per segment | 3 |

## Technology

- Rust + Tokio for the application and transfer engine.
- Tauri 2 and React + TypeScript for the desktop interface.
- russh 0.63.x for async SSH transport.
- russh-sftp 3.0.1 for SFTP v3.

The selected russh 0.63.x line matches the dependency range used by russh-sftp 3.0.1. Russh provides password and public-key authentication, agent-backed signing, a host-key verification callback, and Tokio-native channels. Its client handler rejects host keys by default unless the application explicitly trusts them. TCP_NODELAY will be benchmarked rather than assumed to improve every workload.

## Security principles

- Never store plaintext passwords in connection profiles.
- Use the operating-system credential store for saved secrets.
- Verify SSH host keys and make trust changes explicit; changed keys must never be silently accepted.
- Keep private-key material out of logs and frontend state.
- Use restrictive permissions for temporary transfer state and partial files.
- Treat remote filenames and server-provided metadata as untrusted input.

See docs/architecture.md and docs/transfer-engine.md for implementation constraints.
