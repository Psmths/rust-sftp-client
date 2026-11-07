# Architecture

## High-level layout

The application is split into a desktop presentation layer and a Rust core. The frontend requests operations through narrow Tauri commands; it does not implement SSH, SFTP, credential handling, or file-transfer logic.

    React UI
      ├── Connection manager
      ├── Local file browser
      ├── Remote file browser
      ├── Transfer queue
      └── Settings
            │ Tauri command/event boundary
            ▼
    Rust application layer
      ├── Connection profile and credential services
      ├── SSH connection manager (russh)
      ├── SFTP filesystem service (russh-sftp)
      ├── Transfer scheduler
      │     ├── Single-stream transfer
      │     ├── Segmented download planner
      │     ├── Segmented download workers
      │     ├── Resume/state persistence
      │     └── Retry and integrity checks
      └── Platform integration
            ├── Credential store
            └── Native filesystem

## Design boundaries

- **UI:** renders state and sends user intent; no protocol implementation.
- **Application layer:** validates requests, applies settings, owns transfer lifecycle, and emits progress events.
- **SSH/SFTP layer:** owns authenticated sessions/channels, host-key policy, metadata, reads, writes, and remote filesystem operations.
- **Transfer engine:** schedules bounded work and writes to local files safely.
- **Persistence:** stores non-secret profiles and resumable transfer metadata. Secrets belong in the OS credential manager.

## SSH/SFTP implementation choice

The initial transport is russh 0.63.x with russh-sftp 3.0.1. The SFTP crate 3.0.1 depends on the russh 0.63.2 line, so the application uses the compatible minor line rather than selecting russh 0.65.x independently. Russh is Tokio-native and supports password and public-key authentication, agent-backed signing, a host-key verification callback, and modern SSH algorithms. The SFTP crate exposes a client filesystem API and SFTP v3 support.

The host-key callback is a security boundary: unknown keys must be presented to the user for explicit trust, known keys must match, and changed keys must fail closed. No frontend command may pass a skip-verification switch.

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

## Implementation sequence

1. Establish the Tauri shell and Rust core.
2. Define connection profiles and select a compatible SSH/SFTP stack.
3. Implement host-key verification and password/key/agent authentication.
4. Implement SFTP list/stat/read/write and local/remote panes.
5. Implement a single-stream transfer path and transfer queue.
6. Add segmented download workers, resume, and integrity checks.
7. Add performance instrumentation and reproducible benchmarks.
