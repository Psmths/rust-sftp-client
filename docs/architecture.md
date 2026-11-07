# Architecture

The application is a native Rust desktop program. The UI is rendered directly with egui; there is no embedded browser, JavaScript runtime, or frontend/backend IPC boundary.

    eframe / egui desktop UI
      ├── Session and connection manager
      ├── Local filesystem browser
      ├── Remote SFTP browser
      ├── Transfer queue and telemetry
      └── Settings
            │ Rust application state
            ▼
    Application services
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

- **UI:** renders application state and sends user intent; no protocol implementation.
- **Application layer:** validates requests, applies settings, owns transfer lifecycle, and publishes progress state.
- **SSH/SFTP layer:** owns authenticated sessions/channels, host-key policy, metadata, reads, writes, and remote filesystem operations.
- **Transfer engine:** schedules bounded work and writes to local files safely.
- **Persistence:** stores non-secret profiles and resumable transfer metadata. Secrets belong in the OS credential manager.

## SSH/SFTP implementation choice

The initial transport is russh 0.63.x with russh-sftp 3.0.1. The SFTP crate 3.0.1 depends on the russh 0.63.2 line, so the application uses the compatible minor line. The host-key callback is a security boundary: unknown keys must be presented to the user for explicit trust, known keys must match, and changed keys must fail closed.

## Implementation sequence

1. Establish the native egui desktop shell.
2. Implement host-key verification and password/key/agent authentication.
3. Implement SFTP list/stat/read/write and remote pane.
4. Implement a single-stream transfer path and transfer queue.
5. Add segmented download workers, resume, and integrity checks.
6. Add performance instrumentation and reproducible benchmarks.
