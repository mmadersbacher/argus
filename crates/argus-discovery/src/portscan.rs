//! Async TCP-connect scanner — no raw sockets, no privileges, normal traffic only.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Bytes read from a service's connect-time greeting (one banner line fits).
const BANNER_READ: usize = 512;

/// Max simultaneous port probes per host.
///
/// Bounds total open sockets to `host_concurrency × PER_HOST_CONCURRENCY`, so
/// a wide port list doesn't blow up the file-descriptor budget on large
/// ranges, while a single host still finishes in a couple of timeouts rather
/// than one-per-port (sequential) latency. Kept modest so parallel connects
/// stay gentle on fragile OT/IoT endpoints.
const PER_HOST_CONCURRENCY: usize = 16;

/// Probe `ports` on a single host, returning each open port with the banner
/// the service sent on connect (if any).
///
/// This performs a standard connect (full handshake) and, when `banner_timeout`
/// is `Some`, reads whatever the service volunteers — it NEVER sends a payload
/// first, so it stays safe for fragile OT/IoT devices (a pure connect-and-read
/// looks like any client opening the port). Services that say nothing within
/// the banner timeout (e.g. HTTP, which waits for a request) simply yield no
/// banner. Ports are probed concurrently (bounded by [`PER_HOST_CONCURRENCY`]);
/// the returned list is sorted by port ascending.
pub async fn scan_host(
    ip: IpAddr,
    ports: &[u16],
    connect_timeout: Duration,
    banner_timeout: Option<Duration>,
) -> Vec<(u16, Option<String>)> {
    let mut set: JoinSet<Option<(u16, Option<String>)>> = JoinSet::new();
    let mut open = Vec::new();
    for &port in ports {
        if set.len() >= PER_HOST_CONCURRENCY {
            if let Some(Ok(Some(found))) = set.join_next().await {
                open.push(found);
            }
        }
        set.spawn(async move {
            let addr = SocketAddr::new(ip, port);
            match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    let banner = match banner_timeout {
                        Some(bt) => read_banner(&mut stream, bt).await,
                        None => None,
                    };
                    drop(stream);
                    Some((port, banner))
                }
                _ => None,
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(found)) = res {
            open.push(found);
        }
    }
    open.sort_unstable_by_key(|(port, _)| *port);
    open
}

/// Read a service's connect-time banner WITHOUT sending anything first (the
/// payload-free contract that keeps fragile OT/IoT endpoints safe). Returns the
/// sanitized first line, or `None` if the peer sends nothing within the timeout.
async fn read_banner(stream: &mut TcpStream, banner_timeout: Duration) -> Option<String> {
    let mut buf = [0u8; BANNER_READ];
    match timeout(banner_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => crate::banner::sanitize(&buf[..n]),
        _ => None,
    }
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
    use tokio::io::AsyncWriteExt;

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
        let open: Vec<u16> = scan_host(ip, &probe, Duration::from_millis(500), None)
            .await
            .into_iter()
            .map(|(port, _)| port)
            .collect();
        let mut expected = vec![p1, p2];
        expected.sort_unstable();
        assert_eq!(open, expected);
    }

    #[tokio::test]
    async fn scan_host_skips_closed_ports() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        // A port nobody is listening on should not appear (refused, fast).
        let open = scan_host(ip, &[1], Duration::from_millis(300), None).await;
        assert!(open.iter().all(|(port, _)| *port != 1));
    }

    #[tokio::test]
    async fn scan_host_captures_a_connect_time_banner() {
        // A listener that writes an SSH greeting the instant a client connects —
        // exactly what the scanner must read back without sending anything.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
                let _ = sock.flush().await;
                // Hold the socket briefly so the client reads before close.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let open = scan_host(
            ip,
            &[port],
            Duration::from_millis(500),
            Some(Duration::from_millis(500)),
        )
        .await;
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].1.as_deref(), Some("SSH-2.0-OpenSSH_8.9p1"));
    }

    #[tokio::test]
    async fn silent_service_yields_no_banner_without_hanging() {
        // A listener that accepts but never speaks (like HTTP) must return
        // promptly with no banner, not block for the whole timeout budget.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(200)).await;
                drop(sock);
            }
        });
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let open = scan_host(
            ip,
            &[port],
            Duration::from_millis(500),
            Some(Duration::from_millis(150)),
        )
        .await;
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].1, None);
    }
}
