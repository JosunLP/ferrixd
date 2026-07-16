//! Deterministic host cloaking.
//!
//! A user's real IP is replaced in all *displayed* hostmasks by a stable,
//! HMAC-keyed pseudonym, so `WHOIS`/`JOIN`/messages never leak the address.
//! Server bans (K-/D-Lines) still match the real IP — cloaking is display-only.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Cloak a source IP as `aa.bb.cc.<network>`, keyed by `secret`. The mapping is
/// deterministic (same IP → same cloak) but unforgeable without the key.
#[must_use]
pub fn cloak_ip(secret: &str, ip: &str, network: &str) -> String {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return ip.to_owned();
    };
    mac.update(ip.as_bytes());
    let digest = mac.finalize().into_bytes();
    let hex: String = digest.iter().take(9).map(|b| format!("{b:02x}")).collect();
    format!(
        "{}.{}.{}.{}",
        &hex[0..6],
        &hex[6..12],
        &hex[12..18],
        network
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_hides_ip() {
        let a = cloak_ip("s3cret", "203.0.113.7", "net");
        let b = cloak_ip("s3cret", "203.0.113.7", "net");
        assert_eq!(a, b, "same input must cloak identically");
        assert!(!a.contains("203.0.113.7"), "cloak leaked the IP: {a}");
        assert!(a.ends_with(".net"));
    }

    #[test]
    fn different_ips_and_keys_differ() {
        assert_ne!(cloak_ip("k", "1.1.1.1", "n"), cloak_ip("k", "2.2.2.2", "n"));
        assert_ne!(
            cloak_ip("k1", "1.1.1.1", "n"),
            cloak_ip("k2", "1.1.1.1", "n")
        );
    }
}
