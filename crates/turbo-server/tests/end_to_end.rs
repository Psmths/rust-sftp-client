//! Server and client talking over localhost UDP.
#![cfg(unix)]

use std::{fs, fs::File, io::Write, path::PathBuf};

use rsftp_turbo::server::{Options, Server};
use rsftp_turbo_proto::{
    client::{Connection, FetchError, SegmentFetcher},
    ticket::to_hex,
    Ticket, CHUNK_SIZE, PROTOCOL_VERSION,
};

fn temp_file(name: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rsftp-turbo-e2e-{}-{name}", std::process::id()));
    fs::write(&path, contents).unwrap();
    path
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index.wrapping_mul(31) ^ (index >> 9)) as u8).collect()
}

fn start(options: Options) -> std::sync::Arc<Server> {
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), options).unwrap();
    server.spawn_workers(2).unwrap();
    server
}

fn ticket_for(server: &Server, path: &PathBuf) -> Ticket {
    let file = File::open(path).unwrap();
    let size = file.metadata().unwrap().len();
    let registration = server.register(file, Some("127.0.0.1".parse().unwrap())).unwrap();
    Ticket {
        version: PROTOCOL_VERSION,
        transfer: registration.transfer,
        key: to_hex(&registration.key),
        port: registration.port,
        address: Some("127.0.0.1".into()),
        size,
    }
}

#[tokio::test]
async fn downloads_verified_segments_despite_packet_loss() {
    let contents = pattern(3 * 1024 * 1024 + 777);
    let path = temp_file("lossy", &contents);
    // Every 37th DATA packet is dropped, forcing retransmissions.
    let server = start(Options { drop_data_every: 37 });
    let ticket = ticket_for(&server, &path);
    let connection = Connection::new(server.local_addr().unwrap(), &ticket).unwrap();

    let segment_len = 1024 * 1024 + CHUNK_SIZE / 2; // not chunk aligned on purpose
    let mut downloaded = Vec::new();
    let mut offset = 0_u64;
    let mut fetcher = SegmentFetcher::new(connection.clone()).await.unwrap();
    while (offset as usize) < contents.len() {
        let len = segment_len.min(contents.len() - offset as usize) as u32;
        // Digests are asked for ahead as well; lossy links must not break that.
        let next_offset = offset + u64::from(len);
        let next = ((next_offset as usize) < contents.len())
            .then(|| (next_offset, segment_len.min(contents.len() - next_offset as usize) as u32));
        let mut last_progress = 0;
        let data = fetcher
            .fetch_ahead(offset, len, next, &mut |bytes| last_progress = bytes, &|| false)
            .await
            .unwrap();
        assert_eq!(last_progress, u64::from(len));
        downloaded.extend_from_slice(&data);
        offset += u64::from(len);
    }
    assert_eq!(downloaded, contents);
    connection.close().await;
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn downloads_without_loss_using_batched_sends() {
    // No packet dropping, so on Linux the server uses UDP GSO batches.
    let contents = pattern(5 * 1024 * 1024 + 1234);
    let path = temp_file("batched", &contents);
    let server = start(Options::default());
    let ticket = ticket_for(&server, &path);
    let connection = Connection::new(server.local_addr().unwrap(), &ticket).unwrap();
    let mut fetcher = SegmentFetcher::new(connection.clone()).await.unwrap();
    let mut downloaded = Vec::new();
    let segment = 2 * 1024 * 1024;
    let mut offset = 0;
    while offset < contents.len() {
        let len = segment.min(contents.len() - offset);
        let data = fetcher.fetch(offset as u64, len as u32, &mut |_| {}, &|| false).await.unwrap();
        downloaded.extend_from_slice(&data);
        offset += len;
    }
    assert_eq!(downloaded, contents);
    connection.close().await;
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn digests_asked_for_ahead_are_used_by_the_next_segment() {
    let contents = pattern(6 * 1024 * 1024 + 77);
    let path = temp_file("ahead", &contents);
    let server = start(Options::default());
    let ticket = ticket_for(&server, &path);
    let connection = Connection::new(server.local_addr().unwrap(), &ticket).unwrap();
    let mut fetcher = SegmentFetcher::new(connection.clone()).await.unwrap();
    let segment = 2 * 1024 * 1024;
    let ranges: Vec<(u64, u32)> = (0..contents.len())
        .step_by(segment)
        .map(|offset| (offset as u64, segment.min(contents.len() - offset) as u32))
        .collect();
    let mut downloaded = Vec::new();
    for (index, &(offset, len)) in ranges.iter().enumerate() {
        let next = ranges.get(index + 1).copied();
        let data = fetcher.fetch_ahead(offset, len, next, &mut |_| {}, &|| false).await.unwrap();
        downloaded.extend_from_slice(&data);
    }
    assert_eq!(downloaded, contents);
    // Every segment but the first started with its digest already requested.
    assert_eq!(fetcher.stats().digests_ahead, ranges.len() as u64 - 1);
    connection.close().await;
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn a_file_modified_after_the_ticket_is_refused() {
    let path = temp_file("changing", &pattern(100_000));
    let server = start(Options::default());
    let ticket = ticket_for(&server, &path);
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"appended").unwrap();
    drop(file);

    let connection = Connection::new(server.local_addr().unwrap(), &ticket).unwrap();
    let mut fetcher = SegmentFetcher::new(connection).await.unwrap();
    let result = fetcher.fetch(0, 50_000, &mut |_| {}, &|| false).await;
    assert!(matches!(result, Err(FetchError::FileChanged)), "{result:?}");
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn a_wrong_key_gets_no_answer() {
    let path = temp_file("wrongkey", &pattern(10_000));
    let server = start(Options::default());
    let mut ticket = ticket_for(&server, &path);
    ticket.key = to_hex(&[0_u8; 32]);
    let connection = Connection::new(server.local_addr().unwrap(), &ticket).unwrap();
    let mut fetcher = SegmentFetcher::new(connection).await.unwrap();
    // Cancel quickly instead of waiting for every retry.
    let started = std::time::Instant::now();
    let result = fetcher
        .fetch(0, 10_000, &mut |_| {}, &|| started.elapsed() > std::time::Duration::from_millis(800))
        .await;
    assert!(matches!(result, Err(FetchError::Cancelled)), "{result:?}");
    let _ = fs::remove_file(&path);
}
