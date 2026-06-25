//! Discovery scan pipeline: expand a target, reject private ranges on a hosted
//! server (SSRF guard), run the best available engine, and enrich the result.
//!
//! Pure of HTTP state — it takes a target string and flags and returns hosts —
//! so both the `POST /api/scan` handler and the monitor scheduler share it. The
//! SSRF gate ([`reject_private_targets`]) is the security-relevant core; keeping
//! it here (not buried in `main`) makes it the obvious thing to read and test.

use std::time::Duration;

use axum::http::StatusCode;

/// Outcome of one discovery run: which engine ran and what it found.
pub struct Discovery {
    /// Engine label (`masscan+nmap-os`, `nmap`, or `connect`).
    pub engine: &'static str,
    /// Live hosts found.
    pub hosts: Vec<argus_discovery::DiscoveredHost>,
    /// Number of candidate addresses the target spec expanded to.
    pub candidates: usize,
}

/// Reject a scan whose target expands to any private/internal/special address
/// unless the deployment explicitly allows internal scanning. Stops a hosted,
/// multi-tenant server from being used as an internal-network pivot (SSRF).
/// Shared with the monitor scheduler.
pub fn reject_private_targets(
    ips: &[std::net::IpAddr],
    allow_private: bool,
) -> Result<(), (StatusCode, String)> {
    if allow_private {
        return Ok(());
    }
    if let Some(ip) = ips
        .iter()
        .find(|ip| argus_discovery::is_disallowed_target(**ip))
    {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "target {ip} is in a private/internal range; this server only scans public \
                 addresses. Set ARGUS_SCAN_ALLOW_PRIVATE=true to scan internal networks \
                 (on-prem / self-hosted)."
            ),
        ));
    }
    Ok(())
}

/// Expand `target` and run discovery with the best available engine: the
/// privileged deep path (masscan sweep + nmap SYN/OS, needs root) when
/// requested, else nmap when installed, else the built-in connect scanner.
/// Shared by `POST /api/scan` and the monitor scheduler.
pub async fn discover(
    target: &str,
    deep: bool,
    allow_private: bool,
) -> Result<Discovery, (StatusCode, String)> {
    let ips =
        argus_discovery::expand(target).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    reject_private_targets(&ips, allow_private)?;

    // Deep scan first when requested. Best-effort — an empty result
    // (unprivileged, or nothing live) falls through to the standard
    // nmap/connect path below.
    let deep_hosts = if deep {
        argus_discovery::deep_scan(
            target,
            argus_discovery::fingerprint::PORTS,
            argus_discovery::masscan::DEFAULT_RATE,
            Duration::from_secs(120),
        )
        .await
    } else {
        Vec::new()
    };

    let (engine, mut hosts) = if !deep_hosts.is_empty() {
        ("masscan+nmap-os", deep_hosts)
    } else if argus_discovery::nmap::available().await {
        match argus_discovery::nmap::scan(
            target,
            argus_discovery::fingerprint::PORTS,
            Duration::from_secs(120),
        )
        .await
        {
            Ok(found) => ("nmap", found),
            Err(err) => {
                tracing::warn!(error = %err, "nmap failed; falling back to connect scan");
                let report = argus_discovery::scan(
                    &ips,
                    &argus_discovery::ScanOptions {
                        sample: true,
                        ..Default::default()
                    },
                )
                .await;
                ("connect", report.live)
            }
        }
    } else {
        let report = argus_discovery::scan(
            &ips,
            &argus_discovery::ScanOptions {
                sample: true,
                ..Default::default()
            },
        )
        .await;
        ("connect", report.live)
    };

    // Unified enrichment for every engine: mDNS hostnames/models + MAC/OUI
    // vendor + signal fusion. Makes a Raspberry Pi show up as
    // raspberrypi.local / Raspberry Pi / Linux instead of a bare IP.
    argus_discovery::enrich(&mut hosts, &ips).await;

    Ok(Discovery {
        engine,
        hosts,
        candidates: ips.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn private_targets_are_rejected_unless_allowed() {
        let private: Vec<IpAddr> =
            vec!["10.0.0.5".parse().unwrap(), "192.168.1.1".parse().unwrap()];
        // Hosted server (allow_private = false) refuses an internal target.
        let err = reject_private_targets(&private, false).expect_err("must reject");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        // Self-hosted (allow_private = true) permits it.
        assert!(reject_private_targets(&private, true).is_ok());
    }

    #[test]
    fn public_targets_pass_on_a_hosted_server() {
        let public: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
        assert!(reject_private_targets(&public, false).is_ok());
    }

    #[test]
    fn the_metadata_endpoint_is_rejected() {
        // 169.254.169.254 (cloud metadata) must be refused on a hosted server.
        let meta: Vec<IpAddr> = vec!["169.254.169.254".parse().unwrap()];
        assert!(reject_private_targets(&meta, false).is_err());
    }
}
