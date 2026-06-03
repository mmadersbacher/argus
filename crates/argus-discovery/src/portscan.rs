//! Async TCP-connect scanner — no raw sockets, no privileges, normal traffic only.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// Probe `ports` on a single host, returning those that accept a TCP connection.
///
/// This performs a standard connect (full handshake) and immediately closes —
/// it never sends malformed packets or payloads, which keeps it safe for
/// fragile OT/IoT devices.
pub async fn scan_host(ip: IpAddr, ports: &[u16], connect_timeout: Duration) -> Vec<u16> {
    let mut open = Vec::new();
    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        if let Ok(Ok(stream)) = timeout(connect_timeout, TcpStream::connect(addr)).await {
            drop(stream);
            open.push(port);
        }
    }
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
