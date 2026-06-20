//! Reverse DNS (PTR) via `getent hosts` (shell-out, no resolver dep).
//!
//! A PTR record turns a bare IP into a name for free, and `getent hosts` is the
//! right tool because it goes through NSS — so it honors `/etc/hosts`, the
//! configured DNS resolver (which on a LAN is usually the router, holding DHCP
//! lease names), and `nss-mdns` for `.local` names when installed. That single
//! lookup therefore covers more sources than a raw DNS query would. Best-effort:
//! many LAN clients have no PTR, in which case this returns `None`.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

/// Resolve `ip` to a hostname via the system resolver. `None` if unresolved.
pub async fn lookup(ip: IpAddr, wait: Duration) -> Option<String> {
    let ip_s = ip.to_string();
    let out = timeout(
        wait,
        Command::new("getent")
            .args(["hosts", &ip_s])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    parse_getent(&String::from_utf8_lossy(&out.stdout), ip)
}

/// Parse `getent hosts <ip>` output (`<addr>  <canonical-name>  [aliases…]`),
/// returning the canonical name when it is a real name (not the address echoed
/// back).
fn parse_getent(out: &str, ip: IpAddr) -> Option<String> {
    let ip_s = ip.to_string();
    for line in out.lines() {
        let mut cols = line.split_whitespace();
        let (Some(_addr), Some(name)) = (cols.next(), cols.next()) else {
            continue;
        };
        if name != ip_s {
            return Some(name.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_canonical_name() {
        let out = "192.168.8.1     router.lan\n";
        assert_eq!(
            parse_getent(out, ip("192.168.8.1")).as_deref(),
            Some("router.lan")
        );
    }

    #[test]
    fn name_with_aliases_takes_canonical() {
        let out = "192.168.8.5   nas.local nas\n";
        assert_eq!(
            parse_getent(out, ip("192.168.8.5")).as_deref(),
            Some("nas.local")
        );
    }

    #[test]
    fn empty_or_address_echo_is_none() {
        assert_eq!(parse_getent("", ip("192.168.8.9")), None);
        // Pathological: name column equals the address → no real PTR.
        assert_eq!(
            parse_getent("192.168.8.9  192.168.8.9\n", ip("192.168.8.9")),
            None
        );
    }
}
