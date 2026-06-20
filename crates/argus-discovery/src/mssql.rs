//! SQL Server Browser probe (UDP 1434) — enumerates MSSQL instances + versions.
//!
//! A single `CLNT_UCAST_EX` byte to UDP 1434 makes the SQL Server Browser reply
//! with every instance on the host: server name, instance name, version and the
//! TCP port each listens on. That turns "1433 open" into "MSSQL 15.0.2000.5,
//! instance SQLEXPRESS, tcp 1433" — an exact version for CVE correlation, with no
//! authentication. Read-only: one datagram, no login.

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

/// One MSSQL instance the Browser reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MssqlInstance {
    /// `ServerName` — the host's NetBIOS name.
    pub server: Option<String>,
    /// `InstanceName` — e.g. `MSSQLSERVER`, `SQLEXPRESS`.
    pub instance: Option<String>,
    /// `Version` — e.g. `15.0.2000.5`.
    pub version: Option<String>,
    /// `tcp` — the TCP port this instance listens on.
    pub tcp_port: Option<u16>,
}

/// Ask the SQL Server Browser on `ip` for its instances.
pub async fn query(ip: IpAddr, wait: Duration) -> Option<Vec<MssqlInstance>> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    sock.send_to(&[0x03], (ip, 1434)).await.ok()?; // CLNT_UCAST_EX
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(wait, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse(&buf[..n])
}

/// Parse a Browser response: `0x05`, a 2-byte length, then `key;value` fields
/// with each instance terminated by `;;`. Splitting on `;;` first keeps the
/// per-instance `key;value` pairing aligned (a lone `;;` would otherwise inject
/// an empty token and desync the pairs).
fn parse(resp: &[u8]) -> Option<Vec<MssqlInstance>> {
    if resp.len() < 3 || resp[0] != 0x05 {
        return None;
    }
    let body = String::from_utf8_lossy(&resp[3..]);

    let mut out = Vec::new();
    for chunk in body.split(";;") {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = chunk.split(';').collect();
        let mut inst = MssqlInstance::default();
        let mut i = 0;
        while i + 1 < tokens.len() {
            let value = tokens[i + 1].trim();
            match tokens[i].trim() {
                "ServerName" => inst.server = Some(value.to_owned()),
                "InstanceName" => inst.instance = Some(value.to_owned()),
                "Version" => inst.version = Some(value.to_owned()),
                "tcp" => inst.tcp_port = value.parse().ok(),
                _ => {}
            }
            i += 2;
        }
        if inst != MssqlInstance::default() {
            out.push(inst);
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_single_instance() {
        let mut resp = vec![0x05, 0x00, 0x00];
        resp.extend_from_slice(
            b"ServerName;DBHOST;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.2000.5;tcp;1433;;",
        );
        let inst = parse(&resp).expect("parses");
        assert_eq!(inst.len(), 1);
        assert_eq!(inst[0].server.as_deref(), Some("DBHOST"));
        assert_eq!(inst[0].instance.as_deref(), Some("SQLEXPRESS"));
        assert_eq!(inst[0].version.as_deref(), Some("15.0.2000.5"));
        assert_eq!(inst[0].tcp_port, Some(1433));
    }

    #[test]
    fn parses_multiple_instances() {
        let mut resp = vec![0x05, 0x00, 0x00];
        resp.extend_from_slice(
            b"ServerName;DB;InstanceName;MSSQLSERVER;Version;15.0.1;tcp;1433;;\
              ServerName;DB;InstanceName;SQLEXPRESS;Version;14.0.1;tcp;1434;;",
        );
        let inst = parse(&resp).expect("parses");
        assert_eq!(inst.len(), 2);
        assert_eq!(inst[1].instance.as_deref(), Some("SQLEXPRESS"));
        assert_eq!(inst[1].tcp_port, Some(1434));
    }

    #[test]
    fn rejects_non_browser_response() {
        assert_eq!(parse(b"\x04not-a-browser-reply"), None);
        assert_eq!(parse(&[]), None);
    }
}
