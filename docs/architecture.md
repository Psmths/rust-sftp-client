# Architecture

## High-level layout

The application is split into a desktop presentation layer and a Rust core. The frontend requests operations through narrow Tauri commands; it does not implement SSH, SFTP, credential handling, or file-transfer logic.

```text
React UI
  ├── Connection manager
  ├── Local file browser
  ├── Remote file browser
  ├── Transfer queue
  └── Settings
        │ Tauri command/event boundary
        ▼
Rust application layer
  ├── Profile and credential services
  ├── SSH connection manager
  ├── SFTP filesystem service
  ├── Transfer scheduler
  │     ├── Single-stream transfer
  │     ├── Segmented download
  │     ├── Resume/state persistence
  │     └── Retry and integrity checks
  └── Platform integration
        ├── Credential store
        └── Native filesystem
```

## Design boundaries

- **UI:** renders state and sends user intent; no protocol implementation.
- **Application layer:** validates requests, applies settings, owns transfer lifecycle, and emits progress events.
- **SSH/SFTP layer:** owns authenticated sessions/channels, host-key policy, metadata, reads, writes, and remote filesystem operations.
- **Transfer engine:** schedules bounded work and writes to local files safely.
- **Persistence:** stores non-secret profiles and resumable transfer metadata. Secrets belong in the OS credential manager.

## Connection lifecycle

1. Load a saved profile without loading its secret into frontend state.
2. Resolve credentials through an explicit authentication flow.
3. Establish SSH transport and verify the server host key.
4. Authenticate using the selected method.
5. Open SFTP subsystem/channel and inspect server capabilities/limits where possible.
6. Keep the connection alive according to configured keepalive policy.
7. Close channels and transport deterministically on disconnect or application shutdown.

## Security

- Host-key verification must be on by default. Unknown or changed keys require an explicit user decision.
- Never silently accept changed host keys.
- Do not log passwords, passphrases, private key contents, authentication payloads, or credential-store values.
- Store secrets using platform credential APIs (for example, Windows Credential Manager, macOS Keychain, and a Linux Secret Service-compatible backend).
- Validate remote paths and avoid assuming remote paths follow local operating-system semantics.
- Avoid following symlinks implicitly during recursive operations.
- Use atomic destination replacement where supported.

## Concurrency and resource limits

Concurrency is configurable but bounded. The scheduler must account for per-server limits, per-transfer segment count, global transfer count, file descriptors, memory, and disk throughput. A user setting is a requested ceiling, not permission to overwhelm a server.

TCP_NODELAY, keepalive, and socket buffer options should be exposed only where the underlying SSH transport and platform permit them. TCP congestion control remains an operating-system concern. Benchmark each option before making it a default.

## Initial implementation sequence

1. Establish the Tauri shell and a compilable Rust core.
2. Implement SSH host-key verification and password/key authentication.
3. Implement SFTP list/stat/read/write and local/remote panes.
4. Implement a single-stream transfer path and transfer queue.
5. Add segmented download scheduling and resume.
6. Add performance instrumentation and reproducible benchmarks.
