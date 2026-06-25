//! Anonymous LDAP rootDSE probe (TCP 389, hand-rolled BER, no LDAP crate).
//!
//! Sends one unauthenticated `searchRequest` against the rootDSE (an empty
//! base DN, base scope, `(objectClass=*)` present filter) and reads back the
//! `searchResEntry`. The rootDSE is readable WITHOUT a bind on virtually every
//! directory server, and on Active Directory it hands over the two strongest
//! "this is a Domain Controller" signals for free:
//!
//! * `defaultNamingContext` — the AD domain root DN (e.g. `DC=corp,DC=example,
//!   DC=com`), i.e. the domain itself.
//! * `dnsHostName` — the DC's fully-qualified hostname.
//!
//! Plus `domainFunctionality`, `serverName` and `vendorName` for fingerprint
//! detail. No bind, no writes, no modify — a read-only anonymous query that the
//! protocol explicitly permits against the rootDSE.
//!
//! LDAP is ASN.1 BER over TCP: the same tag/length/value framing as SNMP, so
//! the encoder and the byte-walk decoder mirror the SNMP module's hand-rolled
//! BER rather than pulling in a dependency.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ber::{read_tlv, tlv, tlv_string};

/// Cap on the response read. A rootDSE reply is a handful of short attributes;
/// 16 KiB is generous headroom and bounds a hostile/oversized server.
const RESPONSE_READ: usize = 16 * 1024;

/// rootDSE attributes worth asking for. The first two are the load-bearing
/// Domain-Controller signals; the rest add fingerprint detail.
const ATTRS: &[&str] = &[
    "defaultNamingContext",
    "dnsHostName",
    "domainFunctionality",
    "rootDomainNamingContext",
    "supportedLDAPVersion",
    "serverName",
    "vendorName",
];

/// What the rootDSE told us about a directory server. All fields are optional
/// because a server may answer with only a subset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapRootDse {
    /// `defaultNamingContext` — the AD domain root DN, e.g.
    /// `DC=corp,DC=example,DC=com`. This *is* the Active Directory domain.
    pub default_naming_context: Option<String>,
    /// `dnsHostName` — the Domain Controller's FQDN.
    pub dns_host_name: Option<String>,
    /// `domainFunctionality` — the AD domain functional level (an integer
    /// string, e.g. `7` for Server 2016).
    pub domain_functionality: Option<String>,
    /// `serverName` — the DC's server object DN within the configuration NC.
    pub server_name: Option<String>,
    /// `vendorName` — the directory vendor string, when present.
    pub vendor_name: Option<String>,
}

/// Build the rootDSE `searchRequest` `LDAPMessage` (RFC 4511 §4.5.1).
///
/// `LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp }` where
/// `protocolOp` is `searchRequest [APPLICATION 3]` (tag `0x63`).
#[must_use]
fn build_rootdse_search() -> Vec<u8> {
    let mut req = Vec::new();
    // baseObject: OCTET STRING "" (the rootDSE).
    req.extend_from_slice(&[0x04, 0x00]);
    // scope: ENUMERATED 0 (baseObject).
    req.extend_from_slice(&[0x0A, 0x01, 0x00]);
    // derefAliases: ENUMERATED 0 (neverDerefAliases).
    req.extend_from_slice(&[0x0A, 0x01, 0x00]);
    // sizeLimit: INTEGER 0 (no limit).
    req.extend_from_slice(&[0x02, 0x01, 0x00]);
    // timeLimit: INTEGER 0 (no limit).
    req.extend_from_slice(&[0x02, 0x01, 0x00]);
    // typesOnly: BOOLEAN false.
    req.extend_from_slice(&[0x01, 0x01, 0x00]);
    // filter: present [7] (context-primitive, tag 0x87) = "objectClass".
    req.extend(tlv(0x87, b"objectClass"));
    // attributes: SEQUENCE OF OCTET STRING.
    let mut attrs = Vec::new();
    for attr in ATTRS {
        attrs.extend(tlv(0x04, attr.as_bytes()));
    }
    req.extend(tlv(0x30, &attrs));

    // protocolOp = searchRequest [APPLICATION 3].
    let search = tlv(0x63, &req);

    // LDAPMessage = SEQUENCE { messageID INTEGER 1, protocolOp }.
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x02, 0x01, 0x01]); // messageID = 1
    msg.extend(search);
    tlv(0x30, &msg)
}

/// Probe `ip:port` for the LDAP rootDSE. `None` if it does not answer LDAP.
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<LdapRootDse> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;

    timeout(wait, stream.write_all(&build_rootdse_search()))
        .await
        .ok()?
        .ok()?;

    // Read until the stream stalls or the cap is hit. A DC may split the
    // searchResEntry and the searchResDone across separate segments, so loop.
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        let Ok(Ok(n)) = timeout(wait, stream.read(&mut chunk)).await else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        if buf.len() >= RESPONSE_READ {
            buf.truncate(RESPONSE_READ);
            break;
        }
    }
    drop(stream);
    if buf.is_empty() {
        return None;
    }
    parse_root_dse(&buf)
}

/// Parse an LDAP response and pull the rootDSE attributes we care about.
///
/// The response is a run of one or more `LDAPMessage`s laid end to end. We walk
/// each top-level `SEQUENCE`, skip its `messageID`, and inspect the
/// `protocolOp`. A `searchResEntry` is `[APPLICATION 4]` (tag `0x64`):
///
/// ```text
/// SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
///     objectName  LDAPDN,                 -- OCTET STRING (the rootDSE: empty)
///     attributes  PartialAttributeList }  -- SEQUENCE OF SEQUENCE {
///                                          --   type OCTET STRING,
///                                          --   vals SET OF OCTET STRING }
/// ```
///
/// We skip `objectName`, then for each attribute read its `type` string and the
/// first member of its `vals` SET. `searchResDone` (`0x65`) and any element we
/// do not recognise are skipped via their TLV length. Returns `Some` iff the
/// data parsed as LDAP and at least one wanted field was found.
#[must_use]
fn parse_root_dse(resp: &[u8]) -> Option<LdapRootDse> {
    let mut out = LdapRootDse::default();
    let mut saw_ldap = false;
    let mut pos = 0usize;

    // Walk consecutive LDAPMessage SEQUENCEs.
    while let Some((tag, body, end)) = read_tlv(resp, pos) {
        if tag != 0x30 {
            break; // not a SEQUENCE: not (or no longer) LDAP framing.
        }
        saw_ldap = true;

        // messageID INTEGER, then the protocolOp.
        if let Some((_, _, after_id)) = read_tlv(resp, body) {
            if let Some((op_tag, op_body, op_end)) = read_tlv(resp, after_id) {
                if op_tag == 0x64 {
                    // searchResEntry: harvest its attributes.
                    parse_search_res_entry(resp, op_body, op_end, &mut out);
                }
                // op_tag == 0x65 (searchResDone) and others: nothing to take.
            }
        }

        pos = end;
    }

    if !saw_ldap || out == LdapRootDse::default() {
        return None;
    }
    Some(out)
}

/// Harvest attributes from a `searchResEntry` body spanning `[body, end)`.
fn parse_search_res_entry(resp: &[u8], body: usize, end: usize, out: &mut LdapRootDse) {
    // objectName OCTET STRING (the rootDSE DN, normally empty).
    let Some((_, _, after_name)) = read_tlv(resp, body) else {
        return;
    };
    // attributes: SEQUENCE OF SEQUENCE { type, vals }.
    let Some((attrs_tag, attrs_body, attrs_end)) = read_tlv(resp, after_name) else {
        return;
    };
    if attrs_tag != 0x30 || attrs_end > end {
        return;
    }

    let mut pos = attrs_body;
    while pos < attrs_end {
        let Some((_, pair_body, pair_end)) = read_tlv(resp, pos) else {
            break;
        };
        // type OCTET STRING.
        let Some((type_tag, type_body, type_end)) = read_tlv(resp, pair_body) else {
            pos = pair_end;
            continue;
        };
        if type_tag != 0x04 {
            pos = pair_end;
            continue;
        }
        let name = String::from_utf8_lossy(resp.get(type_body..type_end).unwrap_or_default());

        // vals SET OF OCTET STRING — take the first value, if any.
        let value = read_tlv(resp, type_end).and_then(|(set_tag, set_body, _)| {
            if set_tag != 0x31 {
                return None; // not a SET: malformed, skip.
            }
            let (_, v_body, v_end) = read_tlv(resp, set_body)?;
            tlv_string(resp, v_body, v_end)
        });

        if let Some(value) = value {
            assign_field(out, &name, value);
        }
        pos = pair_end;
    }
}

/// Route a `(attribute, value)` pair into the result struct.
fn assign_field(out: &mut LdapRootDse, name: &str, value: String) {
    // AD attribute names are case-insensitive on the wire.
    if name.eq_ignore_ascii_case("defaultNamingContext") {
        out.default_naming_context = Some(value);
    } else if name.eq_ignore_ascii_case("dnsHostName") {
        out.dns_host_name = Some(value);
    } else if name.eq_ignore_ascii_case("domainFunctionality") {
        out.domain_functionality = Some(value);
    } else if name.eq_ignore_ascii_case("serverName") {
        out.server_name = Some(value);
    } else if name.eq_ignore_ascii_case("vendorName") {
        out.vendor_name = Some(value);
    }
}

// ---------------------------------------------------------------------------
// Anonymous subtree enumeration (the actual misconfiguration finding)
// ---------------------------------------------------------------------------

/// `userAccountControl` flag `DONT_REQ_PREAUTH`: a user that can be
/// AS-REP-roasted (a hash requestable with no credential at all).
const UAC_DONT_REQ_PREAUTH: u32 = 0x0040_0000;

/// What an anonymous `(objectClass=user)` wholeSubtree search returned.
///
/// A populated `users` list means the directory hands its contents to an
/// UNAUTHENTICATED client — the reportable misconfiguration (distinct from the
/// always-readable rootDSE). Empty is the hardened, expected state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubtreeFindings {
    /// A capped sample of `sAMAccountName`s read without any bind.
    pub users: Vec<String>,
    /// `sAMAccountName`s whose `userAccountControl` has `DONT_REQ_PREAUTH`:
    /// AS-REP-roastable with no credential.
    pub asrep_roastable: Vec<String>,
}

/// Build an anonymous `(objectClass=user)` wholeSubtree `searchRequest` under
/// `base_dn`, requesting only `sAMAccountName` + `userAccountControl`,
/// `sizeLimit` 5. messageID 2 (the rootDSE probe used 1).
#[must_use]
fn build_subtree_search(base_dn: &str) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend(tlv(0x04, base_dn.as_bytes())); // baseObject = domain root DN
    req.extend_from_slice(&[0x0A, 0x01, 0x02]); // scope = wholeSubtree (2)
    req.extend_from_slice(&[0x0A, 0x01, 0x00]); // derefAliases = never
    req.extend_from_slice(&[0x02, 0x01, 0x05]); // sizeLimit = 5
    req.extend_from_slice(&[0x02, 0x01, 0x0A]); // timeLimit = 10
    req.extend_from_slice(&[0x01, 0x01, 0x00]); // typesOnly = false
                                                // filter: equalityMatch [3] { attributeDesc "objectClass", value "user" }.
    let mut eq = tlv(0x04, b"objectClass");
    eq.extend(tlv(0x04, b"user"));
    req.extend(tlv(0xA3, &eq));
    // attributes: SEQUENCE OF OCTET STRING.
    let mut attrs = tlv(0x04, b"sAMAccountName");
    attrs.extend(tlv(0x04, b"userAccountControl"));
    req.extend(tlv(0x30, &attrs));

    let search = tlv(0x63, &req); // searchRequest [APPLICATION 3]
    let mut msg = vec![0x02, 0x01, 0x02]; // messageID = 2
    msg.extend(search);
    tlv(0x30, &msg)
}

/// Parse a subtree response: collect `sAMAccountName`s from each
/// `searchResEntry`, flag the AS-REP-roastable ones.
#[must_use]
fn parse_subtree(resp: &[u8]) -> SubtreeFindings {
    let mut out = SubtreeFindings::default();
    let mut pos = 0usize;
    while let Some((tag, body, end)) = read_tlv(resp, pos) {
        if tag != 0x30 {
            break;
        }
        if let Some((_, _, after_id)) = read_tlv(resp, body) {
            if let Some((op_tag, op_body, op_end)) = read_tlv(resp, after_id) {
                if op_tag == 0x64 {
                    if let Some((sam, uac)) = parse_user_entry(resp, op_body, op_end) {
                        if uac.is_some_and(|u| u & UAC_DONT_REQ_PREAUTH != 0) {
                            out.asrep_roastable.push(sam.clone());
                        }
                        if out.users.len() < 50 {
                            out.users.push(sam);
                        }
                    }
                }
            }
        }
        pos = end;
    }
    out
}

/// Pull `(sAMAccountName, userAccountControl)` from one `searchResEntry` body.
fn parse_user_entry(resp: &[u8], body: usize, end: usize) -> Option<(String, Option<u32>)> {
    let (_, _, after_name) = read_tlv(resp, body)?; // objectName (the user DN)
    let (attrs_tag, attrs_body, attrs_end) = read_tlv(resp, after_name)?;
    if attrs_tag != 0x30 || attrs_end > end {
        return None;
    }
    let mut sam: Option<String> = None;
    let mut uac: Option<u32> = None;
    let mut pos = attrs_body;
    while pos < attrs_end {
        let Some((_, pair_body, pair_end)) = read_tlv(resp, pos) else {
            break;
        };
        if let Some((0x04, type_body, type_end)) = read_tlv(resp, pair_body) {
            let name = String::from_utf8_lossy(resp.get(type_body..type_end).unwrap_or_default());
            if let Some((0x31, set_body, _)) = read_tlv(resp, type_end) {
                if let Some((_, v_body, v_end)) = read_tlv(resp, set_body) {
                    if let Some(val) = tlv_string(resp, v_body, v_end) {
                        if name.eq_ignore_ascii_case("sAMAccountName") {
                            sam = Some(val);
                        } else if name.eq_ignore_ascii_case("userAccountControl") {
                            uac = val.trim().parse::<u32>().ok();
                        }
                    }
                }
            }
        }
        pos = pair_end;
    }
    sam.map(|s| (s, uac))
}

/// Anonymously enumerate users under `base_dn` (the AD domain root DN).
///
/// Returns `Some` only if the server handed back directory objects WITHOUT a
/// bind — the misconfiguration. `None` if it answered with no entries
/// (hardened) or did not answer LDAP. Read-only: one searchRequest, no bind.
pub async fn query_users(
    ip: IpAddr,
    port: u16,
    base_dn: &str,
    wait: Duration,
) -> Option<SubtreeFindings> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;
    timeout(wait, stream.write_all(&build_subtree_search(base_dn)))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        let Ok(Ok(n)) = timeout(wait, stream.read(&mut chunk)).await else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        if buf.len() >= RESPONSE_READ {
            buf.truncate(RESPONSE_READ);
            break;
        }
    }
    drop(stream);
    let findings = parse_subtree(&buf);
    (!findings.users.is_empty()).then_some(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_request_is_well_formed() {
        let r = build_rootdse_search();
        assert_eq!(r[0], 0x30, "top SEQUENCE");
        // messageID = 1.
        assert!(
            r.windows(3).any(|w| w == [0x02, 0x01, 0x01]),
            "messageID INTEGER 1"
        );
        // searchRequest [APPLICATION 3].
        assert!(r.contains(&0x63), "searchRequest app tag");
        // present filter [7] over "objectClass": 0x87 0x0B 'o'...
        let mut filter = vec![0x87, 0x0B];
        filter.extend_from_slice(b"objectClass");
        assert!(
            r.windows(filter.len()).any(|w| w == filter.as_slice()),
            "present filter 0x87 over objectClass"
        );
        // Requested attribute names appear verbatim.
        assert!(
            r.windows(20).any(|w| w == b"defaultNamingContext"),
            "defaultNamingContext requested"
        );
        assert!(
            r.windows(11).any(|w| w == b"dnsHostName"),
            "dnsHostName requested"
        );
    }

    /// Build one attribute `SEQUENCE { type OCTET STRING, vals SET { value } }`.
    fn attr(name: &str, value: &str) -> Vec<u8> {
        let mut inner = tlv(0x04, name.as_bytes());
        let set = tlv(0x31, &tlv(0x04, value.as_bytes()));
        inner.extend(set);
        tlv(0x30, &inner)
    }

    fn search_res_entry(attrs: &[(&str, &str)]) -> Vec<u8> {
        // objectName: empty OCTET STRING (the rootDSE).
        let mut entry = vec![0x04, 0x00];
        let mut attr_seq = Vec::new();
        for (n, v) in attrs {
            attr_seq.extend(attr(n, v));
        }
        entry.extend(tlv(0x30, &attr_seq));
        let app4 = tlv(0x64, &entry);

        // Wrap in an LDAPMessage SEQUENCE with messageID 1.
        let mut msg = vec![0x02, 0x01, 0x01];
        msg.extend(app4);
        tlv(0x30, &msg)
    }

    #[test]
    fn parses_default_naming_context_and_dns_host_name() {
        let resp = search_res_entry(&[
            ("defaultNamingContext", "DC=corp,DC=example,DC=com"),
            ("dnsHostName", "dc01.corp.example.com"),
        ]);
        let r = parse_root_dse(&resp).expect("valid searchResEntry parses");
        assert_eq!(
            r.default_naming_context.as_deref(),
            Some("DC=corp,DC=example,DC=com")
        );
        assert_eq!(r.dns_host_name.as_deref(), Some("dc01.corp.example.com"));
    }

    #[test]
    fn collects_the_full_fingerprint_set() {
        let resp = search_res_entry(&[
            ("defaultNamingContext", "DC=corp,DC=example,DC=com"),
            ("dnsHostName", "dc01.corp.example.com"),
            ("domainFunctionality", "7"),
            (
                "serverName",
                "CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com",
            ),
            ("vendorName", "Microsoft Corporation"),
        ]);
        let r = parse_root_dse(&resp).expect("valid searchResEntry parses");
        assert_eq!(r.domain_functionality.as_deref(), Some("7"));
        assert_eq!(r.vendor_name.as_deref(), Some("Microsoft Corporation"));
        assert!(
            r.server_name
                .as_deref()
                .unwrap_or_default()
                .contains("CN=DC01"),
            "serverName harvested"
        );
    }

    #[test]
    fn case_insensitive_attribute_names_match() {
        let resp = search_res_entry(&[("DNSHostName", "dc01.corp.example.com")]);
        let r = parse_root_dse(&resp).expect("valid entry parses");
        assert_eq!(r.dns_host_name.as_deref(), Some("dc01.corp.example.com"));
    }

    #[test]
    fn entry_followed_by_search_res_done_still_parses() {
        // A real DC sends searchResEntry (0x64) then searchResDone (0x65),
        // each in its own LDAPMessage. The trailing Done must not break us.
        let mut resp = search_res_entry(&[("dnsHostName", "dc01.corp.example.com")]);

        // searchResDone [APPLICATION 5]: enumerated result 0, two empty strings.
        let done_body = [0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];
        let done = tlv(0x65, &done_body);
        let mut done_msg = vec![0x02, 0x01, 0x01];
        done_msg.extend(done);
        resp.extend(tlv(0x30, &done_msg));

        let r = parse_root_dse(&resp).expect("entry + done parses");
        assert_eq!(r.dns_host_name.as_deref(), Some("dc01.corp.example.com"));
    }

    #[test]
    fn search_res_done_only_yields_none() {
        // A bare searchResDone (no entry) means the rootDSE gave us nothing.
        let done_body = [0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];
        let done = tlv(0x65, &done_body);
        let mut msg = vec![0x02, 0x01, 0x01];
        msg.extend(done);
        let resp = tlv(0x30, &msg);
        assert_eq!(parse_root_dse(&resp), None);
    }

    #[test]
    fn non_ldap_garbage_is_rejected() {
        assert_eq!(parse_root_dse(&[]), None);
        // HTTP text answering on 389 must not be misread as LDAP.
        assert_eq!(parse_root_dse(b"HTTP/1.1 400 Bad Request\r\n\r\n"), None);
        // A truncated length that overruns the buffer must not panic.
        assert_eq!(parse_root_dse(&[0x30, 0x82, 0xFF, 0xFF]), None);
    }

    /// Build one user `searchResEntry` (objectName DN + sAMAccountName + UAC).
    fn user_entry(dn: &str, sam: &str, uac: &str) -> Vec<u8> {
        let mut entry = tlv(0x04, dn.as_bytes()); // objectName = user DN
        let mut attr_seq = attr("sAMAccountName", sam);
        attr_seq.extend(attr("userAccountControl", uac));
        entry.extend(tlv(0x30, &attr_seq));
        let app4 = tlv(0x64, &entry);
        let mut msg = vec![0x02, 0x01, 0x02]; // messageID 2
        msg.extend(app4);
        tlv(0x30, &msg)
    }

    #[test]
    fn subtree_search_is_well_formed() {
        let r = build_subtree_search("DC=corp,DC=example,DC=com");
        assert_eq!(r[0], 0x30, "top SEQUENCE");
        assert!(r.windows(3).any(|w| w == [0x02, 0x01, 0x02]), "messageID 2");
        assert!(
            r.windows(3).any(|w| w == [0x0A, 0x01, 0x02]),
            "scope wholeSubtree (2)"
        );
        assert!(r.windows(3).any(|w| w == [0x02, 0x01, 0x05]), "sizeLimit 5");
        assert!(r.contains(&0xA3), "equalityMatch filter [3]");
        assert!(
            r.windows(14).any(|w| w == b"sAMAccountName"),
            "sAMAccountName requested"
        );
    }

    #[test]
    fn subtree_parses_users_and_flags_asrep_roastable() {
        // alice = normal (UAC 512); svc-asrep has DONT_REQ_PREAUTH
        // (512 | 0x400000 = 4194816).
        let mut resp = user_entry("CN=alice,DC=corp", "alice", "512");
        resp.extend(user_entry("CN=svc,DC=corp", "svc-asrep", "4194816"));
        let f = parse_subtree(&resp);
        assert_eq!(f.users, vec!["alice".to_owned(), "svc-asrep".to_owned()]);
        assert_eq!(f.asrep_roastable, vec!["svc-asrep".to_owned()]);
    }

    #[test]
    fn subtree_with_no_entries_is_empty() {
        // A bare searchResDone (resultCode 50 = insufficientAccessRights):
        // the hardened directory hands back nothing.
        let done_body = [0x0A, 0x01, 0x32, 0x04, 0x00, 0x04, 0x00];
        let done = tlv(0x65, &done_body);
        let mut msg = vec![0x02, 0x01, 0x02];
        msg.extend(done);
        let resp = tlv(0x30, &msg);
        assert!(parse_subtree(&resp).users.is_empty());
        assert!(parse_subtree(&resp).asrep_roastable.is_empty());
    }
}
