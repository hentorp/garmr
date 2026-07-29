// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Independent per-action argument validation + the reversibility gate — BOTH
//! the agent-side check (on propose) and the executor's independent re-check
//! (on execute). Pure functions over [`ActionKind`], deliberately separate from
//! the execution state machine in [`crate::executor`] so "is this argument safe
//! to act on" has one home and can be tested in isolation.

use garmr_core::ActionKind;

/// Is this action kind reversible? Only reversible actions are ever added to
/// [`ActionKind`]; this is the enforcement point + the place an irreversible
/// future kind would be caught.
pub fn reversible(kind: ActionKind) -> bool {
    match kind {
        ActionKind::BlockIp | ActionKind::IsolateHost => true,
    }
}

/// Strict per-kind argument validation. This is BOTH the agent-side check (on
/// propose) and the executor's independent re-check (on execute).
pub fn validate_arg(kind: ActionKind, arg: &str) -> std::result::Result<(), String> {
    match kind {
        ActionKind::BlockIp => {
            let parsed: std::net::IpAddr = arg.parse().map_err(|_| format!("invalid IP: {arg}"))?;
            // Canonicalize IPv4-mapped/compatible IPv6 (::ffff:10.0.0.1) down to
            // the embedded IPv4 so the RFC1918/loopback screen below actually
            // sees it — otherwise a mapped form slips past the V4 arm.
            let ip = parsed.to_canonical();
            // Never block ourselves or our own networks.
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                return Err(format!(
                    "refusing to block loopback/unspecified/multicast: {arg}"
                ));
            }
            let private = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        // 100.64.0.0/10 CGNAT (RFC 6598) — this deployment's
                        // Tailscale/management overlay; is_private() misses it.
                        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
                }
                // ULA (fc00::/7) or link-local — treat as private.
                std::net::IpAddr::V6(v6) => {
                    (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
            };
            if private {
                return Err(format!(
                    "refusing to block private/CGNAT/RFC1918 address: {arg}"
                ));
            }
            Ok(())
        }
        ActionKind::IsolateHost => {
            // A host name from the event store: conservative charset, so it is
            // safe even if a future path builds a shell string from it.
            if arg.is_empty() || arg.len() > 253 {
                return Err("invalid host length".into());
            }
            // No leading '-' — a host like "--table=nat" would otherwise be
            // parsed as a FLAG by the operator's isolation command (argv
            // injection, even without a shell).
            if arg.starts_with('-') {
                return Err(format!("host name must not start with '-': {arg}"));
            }
            if !arg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return Err(format!("invalid characters in host name: {arg}"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_validation_rejects_private_loopback_and_garbage() {
        assert!(validate_arg(ActionKind::BlockIp, "203.0.113.7").is_ok());
        assert!(validate_arg(ActionKind::BlockIp, "10.0.0.5").is_err());
        assert!(validate_arg(ActionKind::BlockIp, "192.168.1.1").is_err());
        assert!(validate_arg(ActionKind::BlockIp, "127.0.0.1").is_err());
        assert!(validate_arg(ActionKind::BlockIp, "not-an-ip").is_err());
        assert!(validate_arg(ActionKind::BlockIp, "169.254.1.1").is_err());
        assert!(validate_arg(ActionKind::IsolateHost, "pve").is_ok());
        assert!(validate_arg(ActionKind::IsolateHost, "a; rm -rf /").is_err());
        assert!(validate_arg(ActionKind::IsolateHost, "").is_err());
    }

    #[test]
    fn arg_validation_closes_review_gaps() {
        // IPv4-mapped IPv6 must be canonicalized before the private screen.
        assert!(
            validate_arg(ActionKind::BlockIp, "::ffff:10.0.0.1").is_err(),
            "mapped private"
        );
        assert!(
            validate_arg(ActionKind::BlockIp, "::ffff:127.0.0.1").is_err(),
            "mapped loopback"
        );
        // CGNAT / Tailscale management overlay.
        assert!(
            validate_arg(ActionKind::BlockIp, "100.127.71.14").is_err(),
            "CGNAT"
        );
        assert!(validate_arg(ActionKind::BlockIp, "100.64.0.1").is_err());
        // isolate_host must reject a leading '-' (argv/flag injection).
        assert!(validate_arg(ActionKind::IsolateHost, "--table=nat").is_err());
        assert!(validate_arg(ActionKind::IsolateHost, "-x").is_err());
    }
}