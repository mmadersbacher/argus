//! HP PJL / JetDirect printer identity (raw port 9100).
//!
//! Many network printers expose only the raw JetDirect port 9100 — no IPP (631),
//! no mDNS — so neither the IPP probe nor a multicast sweep can name them. PJL
//! (Printer Job Language) is how you ask such a printer what it is: an
//! `@PJL INFO ID` query returns the model string, and `@PJL INFO STATUS` its
//! state. Both are read-only management queries wrapped in the Universal Exit
//! Language escape; they do not enqueue a print job, so a fragile device is not
//! perturbed.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Universal Exit Language — the PJL escape that brackets a command block.
const UEL: &str = "\x1b%-12345X";

/// What a PJL exchange revealed about a printer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PjlInfo {
    /// Model string from `@PJL INFO ID` (e.g. `HP LaserJet 400 M401dne`).
    pub id: Option<String>,
    /// First line of `@PJL INFO STATUS`, if the printer returned one.
    pub status: Option<String>,
}

/// Probe a JetDirect port: send an `@PJL INFO ID` (+ STATUS) block, read the reply.
///
/// `wait` bounds the connect, write and read. Returns `None` if the connection
/// fails, the read is empty, or nothing identifying came back.
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<PjlInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;

    let request = format!("{UEL}@PJL INFO ID\r\n@PJL INFO STATUS\r\n{UEL}\r\n");
    timeout(wait, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let n = timeout(wait, stream.read(&mut buf)).await.ok()?.ok()?;
    drop(stream);
    if n == 0 {
        return None;
    }
    parse_info(&String::from_utf8_lossy(&buf[..n]))
}

/// Parse a PJL `INFO ID` / `INFO STATUS` reply.
///
/// A typical reply is `@PJL INFO ID\r\n"HP LaserJet 400 M401"\r\n` followed by a
/// UEL. The model is the first content line that is not a `@PJL` directive, not
/// the UEL escape, and not empty (quotes stripped). `STATUS` lines like
/// `CODE=10001` are captured separately as the first non-directive status line.
fn parse_info(resp: &str) -> Option<PjlInfo> {
    let mut info = PjlInfo::default();
    let mut section_status = false;
    for line in resp.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("@PJL") {
            section_status = trimmed.contains("STATUS");
            continue;
        }
        let value = trimmed.trim_matches('"').trim();
        if value.is_empty() || value.starts_with('\u{1b}') {
            continue;
        }
        if section_status {
            info.status.get_or_insert_with(|| value.to_owned());
        } else {
            info.id.get_or_insert_with(|| value.to_owned());
        }
    }
    (info != PjlInfo::default()).then_some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_model_id() {
        let resp = "\u{1b}%-12345X@PJL INFO ID\r\n\"HP LaserJet 400 M401dne\"\r\n\u{1b}%-12345X";
        let info = parse_info(resp).expect("a model line parses");
        assert_eq!(info.id.as_deref(), Some("HP LaserJet 400 M401dne"));
    }

    #[test]
    fn parses_id_and_status_sections() {
        let resp = "@PJL INFO ID\r\n\"Brother HL-L2350DW series\"\r\n\
                    @PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\n";
        let info = parse_info(resp).expect("parses");
        assert_eq!(info.id.as_deref(), Some("Brother HL-L2350DW series"));
        assert_eq!(info.status.as_deref(), Some("CODE=10001"));
    }

    #[test]
    fn empty_or_directive_only_is_none() {
        assert_eq!(parse_info(""), None);
        assert_eq!(parse_info("@PJL INFO ID\r\n@PJL INFO STATUS\r\n"), None);
    }
}
