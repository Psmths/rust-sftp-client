# Transfer Engine Design

## Segmented download eligibility

A download is eligible when the remote object is a regular file, meets the configured threshold, SFTP supports offset-based reads, the connection can provide enough independent channels/sessions within server limits, and the destination filesystem supports safe random-access writes. Otherwise use a single stream.

## Range planning

For file size N, segment count K, and segment index i, ranges are half-open:

- start = floor(i * N / K)
- end_exclusive = floor((i + 1) * N / K)
- length = end_exclusive - start

The Rust planner implements balanced contiguous ranges using quotient/remainder arithmetic to avoid multiplication overflow. It validates non-zero segment size and concurrency, handles empty files, respects the configured threshold, and caps the range count.

## Worker model

- A bounded scheduler owns the range queue.
- Each worker uses an independently usable SFTP channel/session.
- Each worker reads only its assigned range using explicit offsets.
- Writes use positional I/O or a serialized writer that preserves offsets.
- Progress is aggregated from confirmed bytes written.
- Cancellation stops scheduling new work and asks active workers to stop cleanly.

## Resume and failure handling

Persist versioned state beside the partial file, including remote identity, destination identity, segment plan, and completed ranges. Revalidate remote metadata before resuming. Retry transient failures with bounded exponential backoff; never retry authentication failures indefinitely. A failed segment must not be marked complete. Fall back to a single stream when parallel reads are unsupported.

## Metrics

Record elapsed time, bytes transferred, effective throughput, retry count, segment count, and per-segment duration. Never include credentials or sensitive key material.
