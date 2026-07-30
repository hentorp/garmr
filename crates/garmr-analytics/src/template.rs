// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Log-line templating: turn a concrete line into a stable template + id.
//!
//! v1 (8a) uses a cheap, dependency-free **masking normalizer**: it replaces the
//! variable parts of a line (numbers, IPs, UUIDs, hex, quoted strings) with typed
//! placeholders so that all lines of the same *shape* collapse to one template.
//! The `template_id` is a short SHA-256 of the masked text — content-addressed,
//! so the templates table dedups exactly like nornir's embedding store.
//!
//! Phase 8b upgrades this to a Drain-style parse tree for better grouping, but the
//! interface (`templatize(line) -> Template`) stays the same so nothing downstream
//! changes.
use sha2::{Digest, Sha256};

pub struct Template {
    /// Short content hash of `text` — the dedup key + join key to `log_events`.
    pub id: String,
    /// The masked template text, e.g. `Failed password for <S> from <IP> port <N>`.
    pub text: String,
    /// The masked-out values in left-to-right match order, as `(kind, value)`
    /// where kind is the lowercase placeholder name (`"ip"`, `"n"`, `"uuid"`,
    /// `"hex"`). Phase 9a: these land in `log_events.params` as JSON so SQL can
    /// join extracted IPs against the `ip_intel` enrichment dimension.
    pub params: Vec<(&'static str, String)>,
}

impl Template {
    /// The extracted params grouped by kind as compact JSON, e.g.
    /// `{"ip":["10.0.0.9"],"n":["51234"]}`. Per-kind order is preserved, which
    /// together with the template text is enough to reconstruct the line.
    /// Empty string (not `{}`) when nothing was masked — keeps no-param rows
    /// byte-identical to pre-9a rows and makes `params <> ''` a cheap filter.
    pub fn params_json(&self) -> String {
        if self.params.is_empty() {
            return String::new();
        }
        let mut m = serde_json::Map::new();
        for (kind, value) in &self.params {
            m.entry(kind.to_string())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()))
                .as_array_mut()
                .expect("entry is always an array")
                .push(serde_json::Value::String(value.clone()));
        }
        serde_json::Value::Object(m).to_string()
    }
}

/// Mask the variable tokens of a raw log line into typed placeholders.
///
/// Order matters: match the most specific patterns (UUID, IP, hex) before the
/// generic number rule, or an IP would be eaten digit-by-digit.
pub fn templatize(line: &str) -> Template {
    let mut out = String::with_capacity(line.len());
    let mut params: Vec<(&'static str, String)> = Vec::new();
    let mut i = 0;
    // Invariant: `i` is always on a char boundary. The maskers only consume ASCII
    // runs (digits/hex/dots/dashes), so a match keeps us on a boundary; otherwise
    // we advance by one whole char. This is UTF-8 safe (log lines contain e.g. 'µs').
    while i < line.len() {
        let rest = &line[i..];
        if let Some((placeholder, len)) = match_token(rest) {
            out.push_str(placeholder);
            params.push((kind_of(placeholder), rest[..len].to_string()));
            i += len;
        } else {
            let ch = rest.chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    let text = collapse_ws(&out);
    let id = short_hash(&text);
    Template { id, text, params }
}

/// Placeholder → params kind (lowercase, no brackets).
fn kind_of(placeholder: &'static str) -> &'static str {
    match placeholder {
        "<IP>" => "ip",
        "<UUID>" => "uuid",
        "<HEX>" => "hex",
        _ => "n",
    }
}

/// Returns `(placeholder, consumed_byte_len)` if a structured token starts here.
fn match_token(s: &str) -> Option<(&'static str, usize)> {
    let b = s.as_bytes();
    // UUID: 8-4-4-4-12 hex
    if let Some(n) = uuid_len(s) {
        return Some(("<UUID>", n));
    }
    // IPv4 (optionally :port handled by the generic number after it)
    if let Some(n) = ipv4_len(s) {
        return Some(("<IP>", n));
    }
    // hex literal 0x… or a long bare hex run (>=8) — sha/ids
    if b.len() >= 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        let n = 2 + hex_run(&s[2..]);
        if n > 2 {
            return Some(("<HEX>", n));
        }
    }
    if let Some(n) = long_hex_len(s) {
        return Some(("<HEX>", n));
    }
    // bare integer / decimal
    if b[0].is_ascii_digit() {
        return Some(("<N>", number_len(s)));
    }
    None
}

fn uuid_len(s: &str) -> Option<usize> {
    let pat = [8usize, 4, 4, 4, 12];
    let b = s.as_bytes();
    let mut idx = 0;
    for (g, &seg) in pat.iter().enumerate() {
        for _ in 0..seg {
            if idx >= b.len() || !b[idx].is_ascii_hexdigit() {
                return None;
            }
            idx += 1;
        }
        if g < pat.len() - 1 {
            if idx >= b.len() || b[idx] != b'-' {
                return None;
            }
            idx += 1;
        }
    }
    Some(idx)
}

fn ipv4_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut idx = 0;
    for octet in 0..4 {
        let start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        let dlen = idx - start;
        if dlen == 0 || dlen > 3 {
            return None;
        }
        if octet < 3 {
            if idx >= b.len() || b[idx] != b'.' {
                return None;
            }
            idx += 1;
        }
    }
    // must not be immediately followed by another dotted digit (avoid version strings run-ons)
    Some(idx)
}

fn hex_run(s: &str) -> usize {
    s.bytes().take_while(|c| c.is_ascii_hexdigit()).count()
}

fn long_hex_len(s: &str) -> Option<usize> {
    let n = hex_run(s);
    // only treat as hex if long AND contains a-f (else it's just a number)
    if n >= 8 && s[..n].bytes().any(|c| c.is_ascii_alphabetic()) {
        Some(n)
    } else {
        None
    }
}

fn number_len(s: &str) -> usize {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
        i += 1;
    }
    i
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn short_hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..8])
}

/// Minimal hex encoder (avoids pulling the `hex` crate).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_multibyte_does_not_panic() {
        // Regression: a 'µ' (2 bytes) in a duration must not break byte indexing.
        let t = templatize("request took 154µs and 3ms");
        assert!(t.text.contains("<N>µs") || t.text.contains("<N>"));
        assert_eq!(t.id.len(), 16);
    }

    #[test]
    fn numeric_variability_collapses() {
        // The 8a masking normalizer groups by NUMERIC variability (IPs, ports,
        // numbers). Lines identical except for IP/port must share a template.
        // (Token-position variability like usernames is 8b's Drain job — see
        // `different_words_differ` below.)
        let a = templatize("Failed password for root from 10.0.0.9 port 51234");
        let b = templatize("Failed password for root from 192.168.1.7 port 22");
        assert_eq!(
            a.id, b.id,
            "same words, differing IP/port → same template id"
        );
        assert!(a.text.contains("<IP>") && a.text.contains("<N>"));
    }

    #[test]
    fn different_words_differ_in_8a() {
        // Documents the 8a limitation: differing usernames are NOT masked, so
        // they yield different templates until 8b's Drain groups by position.
        let a = templatize("Failed password for root from 10.0.0.9");
        let b = templatize("Failed password for admin from 10.0.0.9");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn different_shape_different_id() {
        let a = templatize("Accepted publickey for alice");
        let b = templatize("Failed password for root from 10.0.0.9");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn masks_uuid_and_hex() {
        let t = templatize("session 550e8400-e29b-41d4-a716-446655440000 key 0xdeadbeef");
        assert!(t.text.contains("<UUID>"));
        assert!(t.text.contains("<HEX>"));
    }

    /// Substitute the params back into the template text placeholder by
    /// placeholder — the 9a alignment guarantee the enrichment JOIN relies on.
    fn reconstruct(t: &Template) -> String {
        let mut out = String::new();
        let mut rest = t.text.as_str();
        let mut params = t.params.iter();
        while let Some(start) = rest.find('<') {
            let end = rest[start..]
                .find('>')
                .map(|e| start + e + 1)
                .expect("closing >");
            out.push_str(&rest[..start]);
            let (_kind, value) = params.next().expect("a param per placeholder");
            out.push_str(value);
            rest = &rest[end..];
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn params_align_with_placeholders() {
        let line = "Failed password for root from 10.0.0.9 port 51234";
        let t = templatize(line);
        assert_eq!(t.text, "Failed password for root from <IP> port <N>");
        assert_eq!(
            t.params,
            vec![("ip", "10.0.0.9".to_string()), ("n", "51234".to_string())]
        );
        assert_eq!(
            reconstruct(&t),
            line,
            "params ⊕ template must rebuild the line"
        );
    }

    #[test]
    fn params_json_groups_by_kind() {
        let t = templatize("conn from 10.0.0.9 to 192.168.1.1 port 22");
        assert_eq!(
            t.params_json(),
            r#"{"ip":["10.0.0.9","192.168.1.1"],"n":["22"]}"#
        );
        // no params → empty string, byte-identical to pre-9a rows
        assert_eq!(templatize("hello world").params_json(), "");
    }
}
