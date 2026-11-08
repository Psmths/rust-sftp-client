//! rsftp-turbo — UDP download accelerator for Rust SFTP Client.
//!
//! ```text
//! rsftp-turbo serve [--listen IP[:PORT]] [--socket PATH] [--threads N]
//! rsftp-turbo ticket [--stream] [--socket PATH]   (paths on stdin; used by the client over SSH)
//! rsftp-turbo --version
//! ```

use std::process::ExitCode;

const USAGE: &str = "usage:
  rsftp-turbo serve [--listen IP[:PORT]] [--socket PATH] [--threads N]
      Run the daemon (default: all addresses, port 6767,
      socket /run/rsftp-turbo/turbo.sock, one worker thread per CPU core).
  rsftp-turbo ticket [--stream] [--socket PATH]
      Read a file path from stdin, register it with the daemon and print a
      JSON ticket. With --stream, answer one path per line until stdin
      closes. Run by Rust SFTP Client over SSH.
  rsftp-turbo --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => imp::serve(&args[1..]),
        Some("ticket") => imp::ticket(&args[1..]),
        Some("--version" | "-V" | "version") => {
            println!("rsftp-turbo {} (protocol {})", env!("CARGO_PKG_VERSION"), rsftp_turbo_proto::PROTOCOL_VERSION);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Value of `--name VALUE` in `args`, or `default`.
#[cfg_attr(not(unix), allow(dead_code))]
fn option<'a>(args: &'a [String], name: &str, default: &'a str) -> &'a str {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or(default)
}

#[cfg(unix)]
mod imp {
    use std::{
        net::SocketAddr,
        path::Path,
        process::ExitCode,
        sync::Arc,
        thread,
        time::Duration,
    };

    use rsftp_turbo::{registration, server::Server, ticket, DEFAULT_SOCKET};
    use rsftp_turbo_proto::DEFAULT_PORT;

    use super::option;

    pub fn serve(args: &[String]) -> ExitCode {
        let socket = option(args, "--socket", DEFAULT_SOCKET).to_owned();
        // One receive/send worker per CPU core by default.
        let cores = thread::available_parallelism().map(|cores| cores.get()).unwrap_or(4);
        let threads: usize = option(args, "--threads", "").parse().unwrap_or(cores).clamp(1, 256);
        let server = match bind(args) {
            Ok(server) => server,
            Err(error) => {
                eprintln!("rsftp-turbo: cannot bind UDP socket: {error}");
                return ExitCode::FAILURE;
            }
        };
        let address = server.local_addr().map(|addr| addr.to_string()).unwrap_or_default();
        if let Err(error) = server.spawn_workers(threads) {
            eprintln!("rsftp-turbo: cannot start workers: {error}");
            return ExitCode::FAILURE;
        }
        let janitor = Arc::clone(&server);
        let _ = thread::Builder::new().name("expire".into()).spawn(move || {
            const PERIOD: u64 = 10;
            let mut ticks = 0_u64;
            loop {
                thread::sleep(Duration::from_secs(PERIOD));
                ticks += 1;
                if ticks % 3 == 0 {
                    janitor.expire_idle();
                }
                // Traffic summary while anything is happening (visible in
                // `journalctl -u rsftp-turbo`).
                let report = janitor.take_report();
                if report.requests > 0 || report.data_packets > 0 {
                    eprintln!(
                        "rsftp-turbo: last {PERIOD} s: {} requests, {} data packets ({:.1} MB/s) in {} send calls, \
                         {} send errors, GSO {}, {} active transfers",
                        report.requests,
                        report.data_packets,
                        report.data_bytes as f64 / PERIOD as f64 / 1e6,
                        report.send_calls,
                        report.send_errors,
                        if report.gso { "on" } else { "off" },
                        report.transfers,
                    );
                }
            }
        });
        eprintln!("rsftp-turbo: listening on udp/{address} with {threads} workers, registration socket {socket}");
        match registration::serve(server, Path::new(&socket)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("rsftp-turbo: registration socket {socket}: {error}");
                ExitCode::FAILURE
            }
        }
    }

    /// Binds `--listen`, or dual-stack `[::]` with an IPv4 fallback.
    fn bind(args: &[String]) -> std::io::Result<Arc<Server>> {
        let default_v6: SocketAddr = (std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_PORT).into();
        let default_v4: SocketAddr = (std::net::Ipv4Addr::UNSPECIFIED, DEFAULT_PORT).into();
        match args.iter().position(|arg| arg == "--listen").and_then(|index| args.get(index + 1)) {
            Some(listen) => {
                let addr = parse_listen(listen).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid address {listen} (expected IP or IP:PORT, e.g. 192.168.1.10 or [::]:6767)"),
                    )
                })?;
                Server::bind(addr, Default::default())
            }
            None => Server::bind(default_v6, Default::default()).or_else(|_| Server::bind(default_v4, Default::default())),
        }
    }

    /// `IP:PORT`, `[IPv6]:PORT`, or a bare `IP` / `IPv6` / `[IPv6]` on the default port.
    pub(crate) fn parse_listen(listen: &str) -> Option<SocketAddr> {
        if let Ok(addr) = listen.parse::<SocketAddr>() {
            return Some(addr);
        }
        let ip = listen.trim_start_matches('[').trim_end_matches(']');
        ip.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, DEFAULT_PORT))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_listen;

        #[test]
        fn listen_accepts_addresses_with_and_without_port() {
            assert_eq!(parse_listen("192.168.200.1"), Some("192.168.200.1:6767".parse().unwrap()));
            assert_eq!(parse_listen("192.168.200.1:7000"), Some("192.168.200.1:7000".parse().unwrap()));
            assert_eq!(parse_listen("::"), Some("[::]:6767".parse().unwrap()));
            assert_eq!(parse_listen("[::1]"), Some("[::1]:6767".parse().unwrap()));
            assert_eq!(parse_listen("[::1]:7000"), Some("[::1]:7000".parse().unwrap()));
            assert_eq!(parse_listen("nonsense"), None);
        }
    }

    pub fn ticket(args: &[String]) -> ExitCode {
        let socket = option(args, "--socket", DEFAULT_SOCKET);
        if args.iter().any(|arg| arg == "--stream") {
            return match ticket::run_stream(Path::new(socket)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("rsftp-turbo: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        match ticket::run(Path::new(socket)) {
            Ok(ticket) => match serde_json::to_string(&ticket) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("rsftp-turbo: {error}");
                    ExitCode::FAILURE
                }
            },
            Err(error) => {
                eprintln!("rsftp-turbo: {error}");
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::process::ExitCode;

    pub fn serve(_args: &[String]) -> ExitCode {
        eprintln!("rsftp-turbo runs on Linux/Unix servers only");
        ExitCode::FAILURE
    }

    pub fn ticket(args: &[String]) -> ExitCode {
        serve(args)
    }
}
