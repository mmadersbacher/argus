//! Passive OS/device fingerprinting from an HTTP User-Agent string.
//!
//! Where plaintext HTTP is observed, the `User-Agent` header is a rich, free
//! identity signal — no probing. It is also trivially spoofable, so a match is
//! a hint (Medium), not proof. Pure string analysis; capture is separate.

use argus_core::Confidence;

/// What a `User-Agent` reveals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaGuess {
    /// OS label, if recognised.
    pub os: Option<&'static str>,
    /// Coarse device class (`"mobile"` / `"desktop"`), if inferable.
    pub device_class: Option<&'static str>,
    /// Reliability (User-Agents are spoofable, so never higher than Medium).
    pub confidence: Confidence,
}

/// Classify OS/device from an HTTP `User-Agent`. Order matters: iOS/Android are
/// checked before the generic "mac/linux" substrings they also contain.
#[must_use]
pub fn classify(user_agent: &str) -> UaGuess {
    let ua = user_agent.to_ascii_lowercase();
    let os = if ua.contains("windows nt") {
        Some("Windows")
    } else if ua.contains("android") {
        Some("Android")
    } else if ua.contains("iphone") || ua.contains("ipad") {
        Some("Apple iOS")
    } else if ua.contains("mac os x") || ua.contains("macintosh") {
        Some("Apple macOS")
    } else if ua.contains("linux") {
        Some("Linux")
    } else {
        None
    };
    let device_class = if ua.contains("mobile") || ua.contains("android") || ua.contains("iphone") {
        Some("mobile")
    } else if os.is_some() {
        Some("desktop")
    } else {
        None
    };
    let confidence = if os.is_some() {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    UaGuess {
        os,
        device_class,
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_desktop() {
        let g = classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        assert_eq!(g.os, Some("Windows"));
        assert_eq!(g.device_class, Some("desktop"));
        assert_eq!(g.confidence, Confidence::Medium);
    }

    #[test]
    fn android_mobile() {
        let g = classify("Mozilla/5.0 (Linux; Android 13; Pixel 7) Mobile Safari/537.36");
        assert_eq!(g.os, Some("Android"));
        assert_eq!(g.device_class, Some("mobile"));
    }

    #[test]
    fn iphone_is_ios_not_macos() {
        let g = classify("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)");
        assert_eq!(g.os, Some("Apple iOS"));
        assert_eq!(g.device_class, Some("mobile"));
    }

    #[test]
    fn non_browser_agent_is_unknown() {
        let g = classify("curl/8.4.0");
        assert_eq!(g.os, None);
        assert_eq!(g.confidence, Confidence::Low);
    }
}
