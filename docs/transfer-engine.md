# Transfer Engine Design

## Segmented download eligibility

A download is eligible when all of the following are true:

- The remote object is a regular file.
- Its size is greater than or equal to the configured threshold.
- The SFTP implementation supports offset-based reads.
- The connection can provide enough independent channels/sessions within server limits.
- The destination filesystem supports safe random-access writes.

If any condition fails, use the single-stream implementation.

## Range planning

For file size `N`, segment count `K`, and segment index `i`, compute a half-open byte range:

- `start = floor(i * N / K)`
- `end_exclusive = floor((i + 1) * N / K)`
- `length = end_exclusive - start`

Use checked integer arithmetic. Empty ranges are not scheduled. The final byte offset must never exceed `N - 1`.

The planner should derive a segment count from the configured target segment size and concurrency ceiling. Avoid creating thousands of tiny tasks for very large files.

## Worker model

- A bounded scheduler owns the range queue.
- Each worker uses an independently usable SFTP channel/session.
- Each worker reads only its assigned range using explicit offsets.
- Writes use positional I/O (or a serialized writer that preserves offsets); workers must never share a mutable seek cursor.
- Progress is aggregated from confirmed bytes written, not bytes merely received.
- Cancellation stops scheduling new work and asks active workers to stop cleanly.

## Resume state

Persist a versioned state record beside the partial file. It should include a stable remote identity where available (path, size, modification time, and server/profile identity), destination identity, segment plan, and completed ranges. Do not treat path and size alone as proof that the remote file has not changed.

On resume, revalidate remote metadata. If the remote object changed or state is incompatible, ask before restarting. Write state atomically and protect it with restrictive filesystem permissions.

## Failure handling

- Retry transient network and server errors with bounded exponential backoff and jitter.
- Do not retry authentication failures indefinitely.
- Treat short reads, unexpected EOF, and remote-file mutation as explicit conditions.
- A failed segment must not mark its range complete.
- If parallel reads fail due to server policy, offer or automatically perform a safe single-stream fallback.
- Cancellation and application shutdown must leave a recoverable state when possible.

## Integrity

Always verify the final local length. Prefer a server-provided trusted checksum when available, but do not assume SFTP provides one. A locally computed hash is useful for later verification but does not prove equality with the remote source without a trusted remote digest.

## Metrics and benchmarks

Record elapsed time, bytes transferred, effective throughput, retry count, segment count, and per-segment duration. Never include credentials or sensitive key material.

Benchmark single-stream and segmented modes against representative servers, RTTs, bandwidths, and file sizes. Segmentation should be enabled by default only when measurements demonstrate a benefit and the server supports it safely.
