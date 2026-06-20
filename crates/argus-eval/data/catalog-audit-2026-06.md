# Catalog accuracy audit — argus-vuln catalog vs NVD/vendor (2026-06)

Method: 8 research agents, one NVD/vendor lookup per CVE, each affected-range
cross-checked against >=2 independent sources. Drives FF1: the High-confidence
false positives the FF1 harness reports map 1:1 to the `too_broad` rows below.

**36 ranges match NVD, 28 too_broad (cause High-conf false positives), 7 too_narrow (cause false negatives).**

Root cause of `too_broad`: argus `VersionRange::Range(a,b)` is ONE continuous
inclusive span, but NVD encodes most multi-branch products as SEVERAL disjoint
per-branch ranges with patched gaps. A patched intermediate release falls inside
argus's span and is reported at High confidence. Fix = a multi-range variant.

## Status — resolved for version-checked entries

Added `VersionRange::Branches(&[(start, fixed)])` (disjoint half-open intervals)
and converted the 8 version-checked `too_broad` entries (Samba, MySQL, MariaDB,
libssh, nginx, MongoDB, WordPress, Drupal) plus the 7 `too_narrow` entries
(OpenSSH ×2, Apache, CrushFTP ×3, Memcached). FF1 result: High-tier precision
**0.88 → 1.00** (13 High-confidence false positives → 0), recall **0.95 → 1.00**
(7 missed → 0).

The remaining `too_broad` rows are all `Any` (version-blind) entries —
appliances/cameras/OT (Hikvision, Dahua, Axis, SIMATIC, vCenter, Exchange) where
NVD has no usable remote version signal, and software (Log4j, Spring, Struts,
ActiveMQ, GitLab, PHP, WebLogic, redis, elasticsearch) kept as presence-only
flags so they still correlate on a bare connect-scan. These stay at **Low**
confidence and never drive the risk score, so their patched-version hits are
surfaced-only potentials, not scored false positives. Converting them to
version-checked branches is deferred: it would lose the bare-detection flag and
needs an observed version to be worthwhile.


## too_broad — High-confidence false positives (28)

| CVE | product | argus range | authoritative (NVD/vendor) |
|---|---|---|---|
| CVE-2023-46604 | ActiveMQ | `Any` | Apache ActiveMQ: < 5.15.16, 5.16.0 to < 5.16.7, 5.17.0 to < 5.17.6, 5.18.0 to < 5.18.3 (OpenWire marshaller RCE). Legacy OpenWire Module similarly affected from |
| CVE-2018-10661 | Axis | `Any` | NVD CPE lists 170+ Axis camera models, each with a per-model firmware versionEndExcluding threshold (vulnerable below that firmware), e.g. A1001 < 1.65.1, M1004 |
| CVE-2023-4966 | Citrix | `Any` | NetScaler ADC/Gateway 13.0 before 13.0-92.19; 13.1 before 13.1-49.15; 14.1 before 14.1-8.50; ADC 13.1-FIPS before 13.1-37.164; ADC 12.1-FIPS / 12.1-NDcPP before |
| CVE-2022-26134 | Confluence | `Any` | Confluence Server/Data Center all versions >=1.3.0 through 7.4.16; 7.13.0-7.13.6; 7.14.0-7.14.2; 7.15.0-7.15.1; 7.16.0-7.16.3; 7.17.0-7.17.3; 7.18.0. Effectivel |
| CVE-2021-33044 | Dahua | `Any` | NVD CPE lists per-model firmware versionEndExcluding boundaries, e.g. IPC-HX3XXX < 2.800.0000000.29.r.210630; IPC-HX5XXX < 2.820.0000000.18.r.210705; IPC-HUM7XX |
| CVE-2019-6340 | Drupal | `Range 8.5.0..=8.6.9` | Drupal core 8.5.0 through 8.5.10 (NVD CPE 8.5.0..<8.5.11) AND 8.6.0 through 8.6.9 (NVD CPE 8.6.0..<8.6.10). REST/JSON:API unsanitized-field RCE (SA-CORE-2019-00 |
| CVE-2018-7600 | Drupal | `Any` | Drupal core: 7.x before 7.58; 8.0/8.1/8.2/8.3.x before 8.3.9; 8.4.x before 8.4.6; 8.5.x before 8.5.1 (SA-CORE-2018-002, Drupalgeddon2). |
| CVE-2021-34473 | Exchange | `Any` | Microsoft Exchange Server (on-premises): 2013 CU23 (build 15.00.x < 15.00.1497.015); 2016 CU19 (< 15.01.2176.012) and CU20 (< 15.01.2242.008); 2019 CU8 (< 15.02 |
| CVE-2022-40684 | FortiOS | `Any` | FortiOS 7.0.0-7.0.6 (before 7.0.7) and 7.2.0-7.2.1 (before 7.2.2). NVD CPE for this CVE scopes FortiOS to the 7.0.x and 7.2.x branches only; 6.x and earlier are |
| CVE-2021-22205 | GitLab | `Any` | GitLab CE/EE >= 11.9 and < 13.8.8; >= 13.9 and < 13.9.6; >= 13.10 and < 13.10.3. Unauthenticated RCE via ExifTool/DjVu image parsing. |
| CVE-2021-44228 | Log4j | `Any` | Apache Log4j 2 from 2.0-beta9 up to and including 2.14.1 (NVD/vendor: versionStartIncluding 2.0-beta9, versionEndExcluding 2.15.0). Vendor-precise impacted set: |
| CVE-2021-27928 | MariaDB | `Range 10.2..=10.5.9` | MariaDB 10.2 before 10.2.37, 10.3 before 10.3.28, 10.4 before 10.4.18, 10.5 before 10.5.9 (wsrep_provider / wsrep_notify_cmd untrusted-search-path eval injectio |
| CVE-2025-14847 | MongoDB | `LessThan 8.2.3` | MongoDB Server ('MongoBleed'): Zlib compressed-protocol header length confusion -> unauthenticated read of uninitialized heap memory. Affected per-branch: 8.2 < |
| CVE-2012-2122 | MySQL | `Range 5.1.0..=5.6.5` | Oracle MySQL: 5.1.x before 5.1.63, 5.5.x before 5.5.24, 5.6.x before 5.6.6 (memcmp/return-value auth bypass; only triggers on builds where memcmp returns values |
| CVE-2024-4577 | PHP | `Any` | PHP 8.1.* < 8.1.29, 8.2.* < 8.2.20, 8.3.* < 8.3.8 on Windows when running PHP-CGI under Apache with certain code pages (Best-Fit). PHP 8.0 and earlier are EOL;  |
| CVE-2020-15782 | SIMATIC | `Any` | Siemens SIMATIC S7-1200 CPU family < V4.5.0; SIMATIC S7-1500 CPU family < V2.9.2; SIMATIC Drive Controller family < V2.9.2; SIMATIC S7-1500 Software Controller  |
| CVE-2017-7494 | Samba | `Range 3.5.0..=4.6.4` | Samba since 3.5.0; affected up to but NOT including the per-branch fixes: 3.5.0 through <4.4.0 (all of 3.5/3.6/4.0-4.3 line), 4.4.0 through <4.4.14, 4.5.0 throu |
| CVE-2022-22965 | Spring | `Any` | Spring Framework 5.3.0 through 5.3.17, 5.2.0 through 5.2.19, and all older/unsupported versions (exploit requires JDK 9+, Spring MVC/WebFlux, Tomcat WAR deploym |
| CVE-2017-5638 | Struts | `Any` | Apache Struts 2.3.5 through 2.3.31 (i.e. 2.3.x before 2.3.32) and 2.5 through 2.5.10 (i.e. 2.5.x before 2.5.10.1). Jakarta Multipart parser RCE. |
| CVE-2019-2725 | WebLogic | `Any` | Oracle WebLogic Server 10.3.6.0.0 and 12.1.3.0.0 (Web Services / wls9_async_response, wls-wsat components). Only these two supported branches are affected. |
| CVE-2020-14882 | WebLogic | `Any` | Oracle WebLogic Server (Console component) 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0. |
| CVE-2022-21661 | WordPress | `LessThan 5.8.3` | WordPress core WP_Query/WP_Tax_Query SQL injection. NVD lists per-branch ranges: each minor branch is affected only up to its own backport-patched point release |
| CVE-2015-1427 | elasticsearch | `Any` | Elasticsearch before 1.3.8, and 1.4.0 through 1.4.2 (NVD/MITRE: 'before 1.3.8 and 1.4.x before 1.4.3'). Groovy scripting sandbox bypass -> RCE. KEV-listed. |
| CVE-2018-10933 | libssh | `Range 0.6.0..=0.8.3` | libssh server-side state machine auth bypass (SSH2_MSG_USERAUTH_SUCCESS injection). NVD CPE: 0.6.0 (incl) to <0.7.6 AND 0.8.0 (incl) to <0.8.4. So affected = 0. |
| CVE-2022-41741 | nginx | `Range 1.1.3..=1.23.1` | NVD two ranges for nginx Open Source: 1.1.3 (incl) to 1.22.1 (excl) AND 1.23.0 (incl) to 1.23.2 (excl). I.e. 1.1.3-1.22.0 and 1.23.0-1.23.1 affected; 1.22.1-1.2 |
| CVE-2022-0543 | redis | `Any` | Debian/Ubuntu-PACKAGED Redis only. The Lua sandbox escape (RCE, CVSS 10.0) is introduced by the Debian packaging that dynamically links a system Lua exposing th |
| CVE-2025-49844 | redis | `Any` | All Redis versions with Lua scripting (i.e. Redis >=2.6.0; advisory says 'all versions', GitHub advisory says affected '< 8.2.2' across branches). 'RediShell' L |
| CVE-2021-21972 | vCenter | `Any` | VMware vCenter Server 7.0 before 7.0 U1c; 6.7 before 6.7 U3l; 6.5 before 6.5 U3n. NVD encodes this as enumerated per-update CPEs (not a versionStart/End range), |

## too_narrow — false negatives (missed affected versions) (7)

| CVE | product | argus range | authoritative (NVD/vendor) |
|---|---|---|---|
| CVE-2021-42013 | Apache httpd | `Exact 2.4.50` | Apache HTTP Server 2.4.49 AND 2.4.50 |
| CVE-2024-4040 | CrushFTP | `LessThan 10.7.1` | Two NVD ranges: 10.0.0 (incl) to 10.7.1 (excl) AND 11.0.0 (incl) to 11.1.0 (excl). I.e. all 10.x below 10.7.1 AND all 11.0.x below 11.1.0. |
| CVE-2025-31161 | CrushFTP | `LessThan 10.8.4` | CrushFTP 10.0.0 <= v < 10.8.4 AND CrushFTP 11.0.0 <= v < 11.3.1 (two separate NVD CPE ranges; CNA: <10.8.4 for v10, <11.3.1 for v11) |
| CVE-2025-54309 | CrushFTP | `LessThan 10.8.5` | CrushFTP 10 before 10.8.5 AND CrushFTP 11 before 11.3.4_23 (CNA: v10 <10.8.5, v11 <11.3.4_23) |
| CVE-2016-8706 | Memcached | `AtMost 1.4.31` | Memcached integer overflow in process_bin_sasl_auth (SASL binary-protocol opcode 0x21) -> heap overflow -> RCE. Talos (TALOS-2016-0221) tested/confirmed 1.4.31. |
| CVE-2024-6387 | OpenSSH | `Range 8.5..=9.7` | OpenSSH < 4.4p1, AND 8.5p1 <= version <= 9.7p1 (regression reintroduced in 8.5p1; 4.4-8.4 NOT affected) |
| CVE-2018-15473 | OpenSSH | `LessThan 7.7` | OpenSSH through 7.7 (versionEndIncluding 7.7) |

## matches (no change needed)

CVE-2010-4344 (Exim), CVE-2011-2523 (vsftpd), CVE-2013-2028 (nginx), CVE-2014-0160 (OpenSSL), CVE-2015-1635 (Microsoft-IIS), CVE-2015-3306 (ProFTPD), CVE-2016-3088 (ActiveMQ), CVE-2016-7406 (dropbear), CVE-2017-1000028 (GlassFish), CVE-2017-12615 (Tomcat), CVE-2018-12613 (phpMyAdmin), CVE-2018-15599 (dropbear), CVE-2019-10149 (Exim), CVE-2019-12815 (ProFTPD), CVE-2019-15846 (Exim), CVE-2019-16928 (Exim), CVE-2019-20372 (nginx), CVE-2020-1938 (Tomcat), CVE-2020-28021 (Exim), CVE-2020-9273 (ProFTPD), CVE-2020-9484 (Tomcat), CVE-2021-23017 (nginx), CVE-2021-36260 (Hikvision), CVE-2021-40438 (Apache httpd), CVE-2021-41773 (Apache httpd), CVE-2021-43798 (Grafana), CVE-2022-24706 (CouchDB), CVE-2023-23752 (Joomla), CVE-2023-25690 (Apache httpd), CVE-2023-38408 (OpenSSH), CVE-2023-42115 (Exim), CVE-2023-48795 (OpenSSH), CVE-2023-51713 (ProFTPD), CVE-2024-23897 (Jenkins), CVE-2024-3094 (xz), CVE-2025-24813 (Tomcat)
