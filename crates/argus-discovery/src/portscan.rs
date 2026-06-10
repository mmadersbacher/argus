//! Async TCP-connect scanner — no raw sockets, no privileges, normal traffic only.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Max simultaneous port probes per host.
///
/// Bounds total open sockets to `host_concurrency × PER_HOST_CONCURRENCY`, so
/// a wide port list doesn't blow up the file-descriptor budget on large
/// ranges, while a single host still finishes in a couple of timeouts rather
/// than one-per-port (sequential) latency. Kept modest so parallel connects
/// stay gentle on fragile OT/IoT endpoints.
const PER_HOST_CONCURRENCY: usize = 16;

/// Probe `ports` on a single host, returning those that accept a TCP connection.
///
/// This performs a standard connect (full handshake) and immediately closes —
/// it never sends malformed packets or payloads, which keeps it safe for
/// fragile OT/IoT devices. Ports are probed concurrently (bounded by
/// [`PER_HOST_CONCURRENCY`]); the returned list is sorted ascending.
pub async fn scan_host(ip: IpAddr, ports: &[u16], connect_timeout: Duration) -> Vec<u16> {
    let mut set: JoinSet<Option<u16>> = JoinSet::new();
    let mut open = Vec::new();
    for &port in ports {
        if set.len() >= PER_HOST_CONCURRENCY {
            if let Some(Ok(Some(p))) = set.join_next().await {
                open.push(p);
            }
        }
        set.spawn(async move {
            let addr = SocketAddr::new(ip, port);
            match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    drop(stream);
                    Some(port)
                }
                _ => None,
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(p)) = res {
            open.push(p);
        }
    }
    open.sort_unstable();
    open
}

/// Whether a host shows any sign of life across `ports`.
///
/// Returns `true` on the first port that either accepts a connection (open) or
/// actively refuses it (RST → host is up, port closed). A timeout or unreachable
/// error is treated as no response. Used for cheap subnet sampling.
pub async fn host_responds(ip: IpAddr, ports: &[u16], connect_timeout: Duration) -> bool {
    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => return true,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_host_finds_a_listening_port_and_sorts() {
        // Bind two ephemeral ports; both should come back, in ascending order.
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap().port();
        let p2 = l2.local_addr().unwrap().port();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // Pass the ports high-then-low to prove the result is sorted.
        let mut probe = vec![p1, p2];
        probe.sort_unstable_by(|a, b| b.cmp(a));
        let open = scan_host(ip, &probe, Duration::from_millis(500)).await;
        let mut expected = vec![p1, p2];
        expected.sort_unstable();
        assert_eq!(open, expected);
    }

    #[tokio::test]
    async fn scan_host_skips_closed_ports() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // A port nobody is listening on should not appear (refused, fast).
        let open = scan_host(ip, &[1], Duration::from_millis(300)).await;
        assert!(!open.contains(&1));
    }
}
