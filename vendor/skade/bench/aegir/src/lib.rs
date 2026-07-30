//! Ægir — a tiny pure-Rust S3 client.
//!
//! HTTP + AWS Signature V4 (HMAC-SHA256). No `maybe-async`, no C, no OpenSSL —
//! so it compiles happily alongside `gix` where `rust-s3` can't (gix flips
//! `maybe-async/is_sync` globally and breaks rust-s3's async path). Path-style
//! addressing → works against RustFS / MinIO / real S3.
//!
//! Reads come back as [`bytes::Bytes`] so the body is shared, not re-copied, on
//! the way into arrow/parquet.
//!
//! ## Transports
//!
//! SigV4 signing and the request/response *semantics* are identical regardless
//! of how the bytes move. Only the byte transport is pluggable:
//!
//! - **`ureq`** (default) — pure-Rust HTTP over rustls. Works for TLS and plain.
//! - **`uring`** (opt-in feature) — an io_uring TCP transport for the
//!   **plaintext** hot path (RustFS on `:9000`, no TLS). Built on the pure-Rust
//!   `io-uring` crate (kernel-syscall wrappers; deps are only `libc`/`bitflags`/
//!   `cfg-if` — no C, no bindgen). The socket is connected with `std`'s resolver
//!   and the request/response bytes are pushed/pulled through a per-call
//!   submission/completion loop (`Send`/`Recv` opcodes). TLS endpoints always
//!   fall back to `ureq`, so `uring` is strictly additive.
//!
//! The transport is chosen per [`Client`] via [`Client::with_transport`] (or the
//! `AEGIR_TRANSPORT=uring` env). `ureq` stays the default.

use bytes::Bytes;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::io::Read;

#[cfg(feature = "uring")]
mod uring;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "aegir: {}", self.0)
    }
}
impl std::error::Error for Error {}
impl Error {
    fn new(s: impl Into<String>) -> Self {
        Error(s.into())
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Which byte transport a [`Client`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Pure-Rust HTTP over rustls (`ureq`). The default; handles TLS + plaintext.
    Ureq,
    /// io_uring TCP for the plaintext hot path. Requires the `uring` feature;
    /// TLS endpoints transparently fall back to `ureq`.
    Uring,
}

impl Transport {
    /// Default transport, honouring `AEGIR_TRANSPORT=uring|ureq` if set.
    fn from_env() -> Self {
        match std::env::var("AEGIR_TRANSPORT").ok().as_deref() {
            Some("uring") => Transport::Uring,
            _ => Transport::Ureq,
        }
    }
}

/// A SigV4-signed request, transport-agnostic. Built once by [`Client::signed`],
/// then handed to whichever transport executes it. Keeping this struct between
/// signing and sending is what lets `ureq` and `uring` share identical
/// request/response semantics.
struct SignedReq {
    method: String,
    /// Full URL (`{endpoint}{path}?{query}`).
    url: String,
    /// Header (name, value) pairs to send, in addition to `Host`. Includes the
    /// SigV4 trio (`Authorization`, `x-amz-date`, `x-amz-content-sha256`) plus
    /// any per-op extras (`Content-Type`, `Range`).
    headers: Vec<(String, String)>,
    /// Request body (empty for GET/HEAD/DELETE).
    body: Vec<u8>,
}

impl SignedReq {
    fn header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }
}

/// A transport response: status + headers + body reader. Modeled on the subset
/// of `ureq::Response` the ops use, so both transports return the same shape.
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An S3 client bound to one endpoint + credentials. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    // (Debug impl below — never prints the secret key.)
    endpoint: String, // e.g. http://localhost:9000 (no trailing slash)
    host: String,     // host[:port] — must match the signed Host header
    region: String,
    access_key: String,
    secret_key: String,
    transport: Transport,
    /// `true` when `endpoint` is `https://` (uring cannot speak TLS). Only read
    /// on the `uring` code path.
    #[cfg_attr(not(feature = "uring"), allow(dead_code))]
    tls: bool,
    agent: ureq::Agent,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("aegir::Client")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        let tls = endpoint.starts_with("https://");
        let host = endpoint.split_once("://").map(|(_, h)| h).unwrap_or(&endpoint).to_string();
        Self {
            endpoint,
            host,
            region: region.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            transport: Transport::from_env(),
            tls,
            agent: ureq::agent(),
        }
    }

    /// Select the byte transport. `ureq` is the default; `uring` opts into the
    /// io_uring plaintext path (and is only honoured when the `uring` feature is
    /// compiled — otherwise it's accepted but behaves as `ureq`).
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// The transport actually in effect for this client (after feature/TLS
    /// fallbacks). Useful for benchmark labelling.
    pub fn effective_transport(&self) -> Transport {
        #[cfg(feature = "uring")]
        {
            if self.transport == Transport::Uring && !self.tls {
                return Transport::Uring;
            }
        }
        Transport::Ureq
    }

    /// Build a SigV4-signed request. `canonical_uri` must be the exact, already
    /// percent-encoded path that will be sent.
    fn signed(
        &self,
        method: &str,
        canonical_uri: &str,
        query: &[(&str, &str)],
        body: &[u8],
    ) -> SignedReq {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex(&Sha256::digest(body));

        let mut q: Vec<(String, String)> =
            query.iter().map(|(k, v)| (uri_encode(k, true), uri_encode(v, true))).collect();
        q.sort();
        let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");

        let canonical_headers =
            format!("host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n", self.host, payload_hash, amz_date);
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );

        let k_date = hmac(format!("AWS4{}", self.secret_key).as_bytes(), date_stamp.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );

        let url = if canonical_query.is_empty() {
            format!("{}{}", self.endpoint, canonical_uri)
        } else {
            format!("{}{}?{}", self.endpoint, canonical_uri, canonical_query)
        };
        SignedReq {
            method: method.to_string(),
            url,
            headers: vec![
                ("Authorization".to_string(), authorization),
                ("x-amz-date".to_string(), amz_date),
                ("x-amz-content-sha256".to_string(), payload_hash),
            ],
            body: body.to_vec(),
        }
    }

    /// Execute a signed request through the effective transport. Returns the
    /// parsed response on a 2xx, an [`Error`] otherwise — except this helper is
    /// only used where any non-2xx is an error; callers that special-case a
    /// status (404 on HEAD, 409 on create-bucket) use [`Self::send_raw`].
    fn send(&self, req: SignedReq) -> Result<Resp> {
        let resp = self.send_raw(req)?;
        if (200..300).contains(&resp.status) {
            Ok(resp)
        } else {
            Err(Error::new(format!("http status {}", resp.status)))
        }
    }

    /// Execute a signed request, returning the response regardless of status
    /// (so callers can branch on 404/409). Picks the io_uring transport only for
    /// plaintext when the `uring` feature is on; otherwise `ureq`.
    fn send_raw(&self, req: SignedReq) -> Result<Resp> {
        #[cfg(feature = "uring")]
        {
            if self.transport == Transport::Uring && !self.tls {
                return uring::send(&self.host, &req);
            }
        }
        self.send_ureq(req)
    }

    /// The default `ureq` transport.
    fn send_ureq(&self, req: SignedReq) -> Result<Resp> {
        let mut r = self.agent.request(&req.method, &req.url);
        for (k, v) in &req.headers {
            r = r.set(k, v);
        }
        let res = if req.body.is_empty() {
            r.call()
        } else {
            r.send_bytes(&req.body)
        };
        match res {
            Ok(resp) | Err(ureq::Error::Status(_, resp)) => {
                let status = resp.status();
                let headers = resp
                    .headers_names()
                    .into_iter()
                    .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string())))
                    .collect();
                let cap = resp.header("Content-Length").and_then(|s| s.parse().ok()).unwrap_or(0);
                let mut body = Vec::with_capacity(cap);
                resp.into_reader().read_to_end(&mut body).map_err(|e| Error::new(e.to_string()))?;
                Ok(Resp { status, headers, body })
            }
            Err(e) => Err(map_ureq(e)),
        }
    }

    pub fn put_object(&self, bucket: &str, key: &str, body: &[u8], content_type: Option<&str>) -> Result<()> {
        let uri = format!("/{bucket}/{}", encode_key(key));
        let mut req = self.signed("PUT", &uri, &[], body);
        if let Some(ct) = content_type {
            req.header("Content-Type", ct);
        }
        self.send(req).map(|_| ())
    }

    /// Zero-copy-friendly read: the body is read once into a [`Bytes`] (shared
    /// downstream, never re-copied).
    pub fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes> {
        let uri = format!("/{bucket}/{}", encode_key(key));
        let resp = self.send(self.signed("GET", &uri, &[], b""))?;
        Ok(Bytes::from(resp.body))
    }

    pub fn head_object(&self, bucket: &str, key: &str) -> Result<bool> {
        Ok(self.head_size(bucket, key)?.is_some())
    }

    /// HEAD → the object's size, or `None` if it doesn't exist.
    pub fn head_size(&self, bucket: &str, key: &str) -> Result<Option<u64>> {
        let uri = format!("/{bucket}/{}", encode_key(key));
        let resp = self.send_raw(self.signed("HEAD", &uri, &[], b""))?;
        match resp.status {
            404 => Ok(None),
            s if (200..300).contains(&s) => {
                Ok(Some(resp.header("Content-Length").and_then(|s| s.parse().ok()).unwrap_or(0)))
            }
            s => Err(Error::new(format!("http status {s}"))),
        }
    }

    /// Ranged GET (`bytes=start-end`, end inclusive) → [`Bytes`].
    pub fn get_object_range(&self, bucket: &str, key: &str, start: u64, end_inclusive: u64) -> Result<Bytes> {
        let uri = format!("/{bucket}/{}", encode_key(key));
        let mut req = self.signed("GET", &uri, &[], b"");
        req.header("Range", &format!("bytes={start}-{end_inclusive}"));
        let resp = self.send(req)?;
        Ok(Bytes::from(resp.body))
    }

    pub fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let uri = format!("/{bucket}/{}", encode_key(key));
        let resp = self.send_raw(self.signed("DELETE", &uri, &[], b""))?;
        // S3 DELETE returns 204; some stores 200/404 (already gone) — all fine.
        if resp.status == 404 || (200..300).contains(&resp.status) {
            Ok(())
        } else {
            Err(Error::new(format!("http status {}", resp.status)))
        }
    }

    pub fn create_bucket(&self, bucket: &str) -> Result<()> {
        let uri = format!("/{bucket}");
        let resp = self.send_raw(self.signed("PUT", &uri, &[], b""))?;
        match resp.status {
            // already owned / exists — both fine for idempotent ensure.
            409 => Ok(()),
            s if (200..300).contains(&s) => Ok(()),
            s => Err(Error::new(format!("create_bucket http status {s}"))),
        }
    }

    /// List keys under `prefix` (ListObjectsV2). Hand-parses `<Key>` from the XML
    /// to stay dependency-light.
    pub fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<String>> {
        let uri = format!("/{bucket}");
        let resp = self.send(self.signed("GET", &uri, &[("list-type", "2"), ("prefix", prefix)], b""))?;
        let body = String::from_utf8_lossy(&resp.body);
        Ok(body
            .split("<Key>")
            .skip(1)
            .filter_map(|s| s.split("</Key>").next())
            .map(xml_unescape)
            .collect())
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// AWS URI-encode: unreserved = `A-Za-z0-9-_.~`; everything else `%XX` (upper).
/// `/` is kept when `encode_slash` is false (object keys are path-segmented).
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn encode_key(key: &str) -> String {
    uri_encode(key.trim_start_matches('/'), false)
}

fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
}

fn map_ureq(e: ureq::Error) -> Error {
    Error::new(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encode_keeps_slashes_in_keys() {
        assert_eq!(encode_key("wh/data/file.parquet"), "wh/data/file.parquet");
        assert_eq!(uri_encode("a b+c", true), "a%20b%2Bc");
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // Known-answer SigV4 signing-key chain (AWS docs example).
    #[test]
    fn sigv4_signing_key_matches_aws_example() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), b"20150830");
        let k_region = hmac(&k_date, b"us-east-1");
        let k_service = hmac(&k_region, b"iam");
        let k_signing = hmac(&k_service, b"aws4_request");
        assert_eq!(
            hex(&k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    // SigV4 signing is identical regardless of transport: `signed()` produces the
    // same Authorization header whether the bytes later go out via ureq or uring.
    #[test]
    fn signed_request_carries_sigv4_trio() {
        let c = Client::new("http://localhost:9000", "us-east-1", "ak", "sk");
        let req = c.signed("GET", "/warehouse/wh/x", &[], b"");
        assert_eq!(req.method, "GET");
        assert_eq!(c.host, "localhost:9000");
        assert!(req.headers.iter().any(|(k, v)| k == "Authorization"
            && v.starts_with("AWS4-HMAC-SHA256 Credential=ak/")));
        assert!(req.headers.iter().any(|(k, _)| k == "x-amz-date"));
        assert!(req.headers.iter().any(|(k, _)| k == "x-amz-content-sha256"));
    }

    #[test]
    fn tls_endpoint_never_uses_uring() {
        let c = Client::new("https://s3.amazonaws.com", "us-east-1", "ak", "sk")
            .with_transport(Transport::Uring);
        // https → uring must fall back to ureq even when requested.
        assert_eq!(c.effective_transport(), Transport::Ureq);
    }
}
