//! Cookie-based session transport and double-submit CSRF.
//!
//! The browser console authenticates with an `HttpOnly` session cookie holding
//! the JWT, so the token is never readable from JavaScript. Because the cookie
//! is sent ambiently by the browser, every state-changing request must also
//! prove it originated from the console, not a malicious cross-site page: the
//! server sets a second, JS-readable CSRF cookie and the console echoes its
//! value in the [`CSRF_HEADER`]. The server accepts the request only when the
//! header matches the cookie ([`csrf_ok`]) — a stateless *double-submit*. A
//! cross-site attacker can neither read the victim's CSRF cookie nor set a
//! custom request header without a CORS preflight the API denies, so the echo
//! cannot be forged.
//!
//! Cookie security attributes are resolved once from the environment so a
//! cross-origin HTTPS deployment gets `Secure; SameSite=None` by default while
//! local plain-HTTP dev can opt down to `SameSite=Lax` without `Secure`.

use axum::http::{HeaderMap, Method};
use rand::RngCore;

use crate::env_flag;

/// `HttpOnly` cookie carrying the session JWT (never visible to JS).
pub const SESSION_COOKIE: &str = "argus_session";
/// JS-readable cookie carrying the CSRF token the console echoes back.
pub const CSRF_COOKIE: &str = "argus_csrf";
/// Request header the console sets to the CSRF cookie's value.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// `SameSite` attribute for the session/CSRF cookies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    /// Sent on same-site requests only, including top-level cross-site GETs.
    Lax,
    /// Sent on same-site requests only, never on cross-site navigation.
    Strict,
    /// Sent on cross-site requests too (requires `Secure`).
    None,
}

impl SameSite {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

/// Cookie security attributes, resolved once from the environment.
#[derive(Clone, Copy, Debug)]
pub struct CookieConfig {
    /// Whether the `Secure` attribute is set (HTTPS-only delivery).
    pub secure: bool,
    /// The `SameSite` attribute.
    pub same_site: SameSite,
}

impl CookieConfig {
    /// Resolve from the environment.
    ///
    /// Defaults to `Secure; SameSite=None` — correct for a cross-origin console
    /// served over HTTPS. For local plain-HTTP dev set `ARGUS_COOKIE_SECURE=false`
    /// and `ARGUS_COOKIE_SAMESITE=Lax`: the console (`localhost:3000`) and API
    /// (`localhost:8088`) share the `localhost` site, so `Lax` cookies are still
    /// sent on the cross-origin fetch.
    #[must_use]
    pub fn from_env() -> Self {
        let secure = env_flag("ARGUS_COOKIE_SECURE", true);
        let same_site = match std::env::var("ARGUS_COOKIE_SAMESITE")
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("Lax" | "lax") => SameSite::Lax,
            Some("Strict" | "strict") => SameSite::Strict,
            Some("None" | "none" | "") | None => SameSite::None,
            Some(other) => {
                tracing::warn!(value = other, "unknown ARGUS_COOKIE_SAMESITE — using None");
                SameSite::None
            }
        };
        if same_site == SameSite::None && !secure {
            tracing::warn!(
                "ARGUS_COOKIE_SAMESITE=None requires Secure cookies; browsers reject \
                 them over plain HTTP (except on localhost). Set ARGUS_COOKIE_SECURE=true \
                 in production or SameSite=Lax for same-site dev."
            );
        }
        Self { secure, same_site }
    }

    /// Build a `Set-Cookie` value for `name=value`, expiring in `max_age_secs`.
    #[must_use]
    pub fn set(self, name: &str, value: &str, max_age_secs: i64, http_only: bool) -> String {
        let mut c = format!(
            "{name}={value}; Path=/; Max-Age={max_age_secs}; SameSite={}",
            self.same_site.as_str()
        );
        if http_only {
            c.push_str("; HttpOnly");
        }
        if self.secure {
            c.push_str("; Secure");
        }
        c
    }

    /// Build a `Set-Cookie` value that immediately clears `name`.
    #[must_use]
    pub fn clear(self, name: &str, http_only: bool) -> String {
        self.set(name, "", 0, http_only)
    }
}

/// Read a named cookie's value from a request's `Cookie` header.
#[must_use]
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// A fresh, unguessable CSRF token (32 random bytes, hex-encoded).
#[must_use]
pub fn new_csrf_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Whether an HTTP method mutates state and therefore needs CSRF protection.
/// The safe, side-effect-free methods (`GET`/`HEAD`/`OPTIONS`) are exempt.
#[must_use]
pub fn is_unsafe_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Double-submit CSRF decision for a cookie-authenticated request.
///
/// Safe methods always pass. Unsafe methods pass only when both the CSRF
/// cookie and the [`CSRF_HEADER`] are present, non-empty, and equal (compared
/// in constant time so a timing side-channel cannot reveal the token).
#[must_use]
pub fn csrf_ok(method: &Method, cookie: Option<&str>, header: Option<&str>) -> bool {
    if !is_unsafe_method(method) {
        return true;
    }
    matches!(
        (cookie, header),
        (Some(c), Some(h)) if !c.is_empty() && ct_eq(c, h)
    )
}

/// Constant-time string equality. Returns early only on a length mismatch
/// (token length is fixed and public), never on content.
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::COOKIE, value.parse().unwrap());
        h
    }

    #[test]
    fn reads_a_named_cookie_among_several() {
        let h = headers_with_cookie("argus_session=jwt.abc.def; argus_csrf=deadbeef; other=1");
        assert_eq!(
            read_cookie(&h, SESSION_COOKIE).as_deref(),
            Some("jwt.abc.def")
        );
        assert_eq!(read_cookie(&h, CSRF_COOKIE).as_deref(), Some("deadbeef"));
        assert_eq!(read_cookie(&h, "missing"), None);
    }

    #[test]
    fn missing_cookie_header_is_none() {
        assert_eq!(read_cookie(&HeaderMap::new(), SESSION_COOKIE), None);
    }

    #[test]
    fn set_cookie_carries_the_configured_attributes() {
        let cfg = CookieConfig {
            secure: true,
            same_site: SameSite::None,
        };
        let session = cfg.set(SESSION_COOKIE, "token", 3600, true);
        assert!(session.contains("argus_session=token"));
        assert!(session.contains("HttpOnly"));
        assert!(session.contains("Secure"));
        assert!(session.contains("SameSite=None"));
        assert!(session.contains("Max-Age=3600"));

        // The CSRF cookie must be readable by JS — never HttpOnly.
        let csrf = cfg.set(CSRF_COOKIE, "tok", 3600, false);
        assert!(!csrf.contains("HttpOnly"));
    }

    #[test]
    fn dev_config_omits_secure_and_uses_lax() {
        let cfg = CookieConfig {
            secure: false,
            same_site: SameSite::Lax,
        };
        let c = cfg.set(SESSION_COOKIE, "t", 3600, true);
        assert!(!c.contains("Secure"));
        assert!(c.contains("SameSite=Lax"));
    }

    #[test]
    fn clear_sets_max_age_zero() {
        let cfg = CookieConfig {
            secure: true,
            same_site: SameSite::None,
        };
        assert!(cfg.clear(SESSION_COOKIE, true).contains("Max-Age=0"));
    }

    #[test]
    fn safe_methods_skip_csrf() {
        assert!(csrf_ok(&Method::GET, None, None));
        assert!(csrf_ok(&Method::HEAD, None, None));
        assert!(csrf_ok(&Method::OPTIONS, None, None));
    }

    #[test]
    fn unsafe_methods_require_a_matching_double_submit() {
        // Missing either side fails.
        assert!(!csrf_ok(&Method::POST, None, None));
        assert!(!csrf_ok(&Method::POST, Some("tok"), None));
        assert!(!csrf_ok(&Method::POST, None, Some("tok")));
        // A mismatch fails.
        assert!(!csrf_ok(&Method::POST, Some("tok"), Some("nope")));
        // An empty cookie never passes, even if the header echoes it.
        assert!(!csrf_ok(&Method::POST, Some(""), Some("")));
        // A genuine match passes.
        assert!(csrf_ok(&Method::POST, Some("tok"), Some("tok")));
        assert!(csrf_ok(&Method::DELETE, Some("abc"), Some("abc")));
        assert!(csrf_ok(&Method::PATCH, Some("abc"), Some("abc")));
    }

    #[test]
    fn ct_eq_matches_string_equality() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(ct_eq("", ""));
    }
}
