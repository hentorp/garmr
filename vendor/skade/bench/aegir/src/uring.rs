//! io_uring TCP transport for the **plaintext** S3 hot path (RustFS on `:9000`,
//! no TLS).
//!
//! This is opt-in (`uring` feature) and strictly additive: it only ever handles
//! `http://` endpoints — the [`super::Client::send_raw`] dispatcher routes TLS
//! through `ureq`. SigV4 + the request/response semantics are untouched; this
//! module just moves the already-signed bytes.
//!
//! ## Design
//!
//! Pure Rust, no C: the `io-uring` crate is thin syscall wrappers (its only deps
//! are `libc` FFI declarations, `bitflags`, `cfg-if` — no `bindgen`, no OpenSSL).
//!
//! - **Connect**: with `std::net::TcpStream` (std's resolver, `TCP_NODELAY`).
//!   io_uring's own `Connect` opcode needs a hand-built sockaddr; using std for
//!   the one-time connect keeps the code small and leaves the *data path* (the
//!   hot part) on io_uring.
//! - **Transfer**: each call drives `Send` (the whole request) then a `Recv`
//!   loop (the response) via the io_uring submission/completion queues — a real
//!   SQE/CQE loop, the minimal io_uring data-path the task asked for.
//! - **Keep-alive pool**: connections are pooled **per-thread** keyed by host
//!   (`HTTP/1.1` keep-alive). This matches `ureq`'s pooled-agent model so the
//!   ureq-vs-uring comparison is apples-to-apples (one TCP handshake amortised
//!   over many ops, not one per op). The io_uring instance is owned by the
//!   pooled connection and reused. A connection that errors or is closed by the
//!   peer is dropped and re-established on the next call.
//! - **Response framing**: `Content-Length` (the common case for object GET/PUT/
//!   HEAD) or `Transfer-Encoding: chunked` (list XML). HEAD never has a body even
//!   when `Content-Length` is advertised, so the method drives that decision.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write as _;
use std::net::TcpStream;
use std::os::fd::AsRawFd;

use io_uring::{opcode, types, IoUring};

use crate::{Error, Resp, Result, SignedReq};

fn err(e: impl std::fmt::Display) -> Error {
    Error::new(e.to_string())
}

/// One pooled keep-alive connection: a TCP stream + its own io_uring instance +
/// a reusable receive buffer.
struct Conn {
    stream: TcpStream,
    ring: IoUring,
    rbuf: Vec<u8>,
}

impl Conn {
    fn connect(host: &str) -> Result<Self> {
        let stream = TcpStream::connect(host).map_err(err)?;
        stream.set_nodelay(true).ok();
        let ring = IoUring::new(8).map_err(err)?;
        Ok(Self { stream, ring, rbuf: vec![0u8; 64 * 1024] })
    }

    /// Send the request bytes via io_uring `Send` (looped until fully drained).
    fn send_all(&mut self, raw: &[u8]) -> Result<()> {
        let fd = types::Fd(self.stream.as_raw_fd());
        let mut sent = 0usize;
        while sent < raw.len() {
            let chunk = &raw[sent..];
            let sqe = opcode::Send::new(fd, chunk.as_ptr(), chunk.len() as u32)
                .build()
                .user_data(0x5e4d);
            // SAFETY: `raw` outlives this submit_and_wait; `fd` is valid; one
            // in-flight op at a time on this ring.
            unsafe { self.ring.submission().push(&sqe).map_err(err)?; }
            self.ring.submit_and_wait(1).map_err(err)?;
            let cqe = self.ring.completion().next().ok_or_else(|| err("send: empty CQE"))?;
            let n = cqe.result();
            if n < 0 {
                return Err(err(format!("send failed: errno {}", -n)));
            }
            if n == 0 {
                return Err(err("send: peer closed before request drained"));
            }
            sent += n as usize;
        }
        Ok(())
    }

    /// Read into `out` via one io_uring `Recv`. Returns bytes read (0 = EOF).
    fn recv_once(&mut self, out: &mut Vec<u8>) -> Result<usize> {
        let fd = types::Fd(self.stream.as_raw_fd());
        let sqe = opcode::Recv::new(fd, self.rbuf.as_mut_ptr(), self.rbuf.len() as u32)
            .build()
            .user_data(0x4ec4);
        // SAFETY: `rbuf` outlives the wait; `fd` valid; single in-flight op.
        unsafe { self.ring.submission().push(&sqe).map_err(err)?; }
        self.ring.submit_and_wait(1).map_err(err)?;
        let cqe = self.ring.completion().next().ok_or_else(|| err("recv: empty CQE"))?;
        let n = cqe.result();
        if n < 0 {
            return Err(err(format!("recv failed: errno {}", -n)));
        }
        if n > 0 {
            out.extend_from_slice(&self.rbuf[..n as usize]);
        }
        Ok(n as usize)
    }
}

thread_local! {
    /// Per-thread keep-alive connection pool, keyed by `host[:port]`. One pooled
    /// connection per host is enough: aegir ops are serial within a thread, and
    /// the bench runs one writer per OS thread.
    static POOL: RefCell<HashMap<String, Conn>> = RefCell::new(HashMap::new());
}

/// Send a signed request over a pooled io_uring TCP connection and parse the
/// response. `host` is the `host[:port]` to connect to (must match the signed
/// `Host`). On any connection-level error the pooled conn is dropped and one
/// retry on a fresh connection is attempted (keep-alive races / idle closes).
pub(crate) fn send(host: &str, req: &SignedReq) -> Result<Resp> {
    let raw = serialize_request(host, req);
    let head_request = req.method.eq_ignore_ascii_case("HEAD");

    // First try: reuse (or establish) the pooled connection.
    match round_trip(host, &raw, head_request, true) {
        Ok(resp) => Ok(resp),
        // A pooled connection may have been closed by the peer while idle; retry
        // once on a guaranteed-fresh connection.
        Err(_) => round_trip(host, &raw, head_request, false),
    }
}

/// One request/response over a pooled connection. `reuse=false` forces a fresh
/// connection (used for the single retry).
fn round_trip(host: &str, raw: &[u8], head_request: bool, reuse: bool) -> Result<Resp> {
    POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if !reuse {
            pool.remove(host);
        }
        if !pool.contains_key(host) {
            pool.insert(host.to_string(), Conn::connect(host)?);
        }
        let conn = pool.get_mut(host).expect("just inserted");

        let result = (|| {
            conn.send_all(raw)?;
            let mut resp = Vec::with_capacity(8 * 1024);
            loop {
                if let Some((status, headers, body, keep_alive)) =
                    try_parse(&resp, head_request)?
                {
                    return Ok((Resp { status, headers, body }, keep_alive));
                }
                let n = conn.recv_once(&mut resp)?;
                if n == 0 {
                    // EOF: parse whatever we have (close-delimited body).
                    return match try_parse_eof(&resp, head_request)? {
                        Some((status, headers, body)) => Ok((Resp { status, headers, body }, false)),
                        None => Err(err("connection closed before full response")),
                    };
                }
            }
        })();

        match result {
            Ok((resp, keep_alive)) => {
                if !keep_alive {
                    pool.remove(host);
                }
                Ok(resp)
            }
            Err(e) => {
                // Poison the connection so the retry doesn't reuse a broken one.
                pool.remove(host);
                Err(e)
            }
        }
    })
}

/// Build the raw HTTP/1.1 request bytes (request line + headers + body).
/// Keep-alive (the HTTP/1.1 default) so the pooled connection survives.
fn serialize_request(host: &str, req: &SignedReq) -> Vec<u8> {
    // Path+query for the request line: strip scheme://authority from the URL.
    let path = req
        .url
        .split_once("://")
        .and_then(|(_, rest)| match rest.split_once('/') {
            Some((_, p)) => Some(format!("/{p}")),
            None => None,
        })
        .unwrap_or_else(|| "/".to_string());

    let mut out = Vec::with_capacity(256 + req.body.len());
    let _ = write!(out, "{} {} HTTP/1.1\r\n", req.method, path);
    let _ = write!(out, "Host: {host}\r\n");
    let _ = write!(out, "Content-Length: {}\r\n", req.body.len());
    for (k, v) in &req.headers {
        let _ = write!(out, "{k}: {v}\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

/// Parsed response headers + how the body is framed.
struct Head {
    status: u16,
    headers: Vec<(String, String)>,
    content_length: Option<usize>,
    chunked: bool,
    keep_alive: bool,
}

fn parse_head(resp: &[u8]) -> Result<Option<(usize, Head)>> {
    let Some(sep) = find_crlfcrlf(resp) else { return Ok(None) };
    let head = String::from_utf8_lossy(&resp[..sep]).to_string();
    let mut lines = head.lines();

    let status_line = lines.next().ok_or_else(|| err("empty response"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| err(format!("bad status line: {status_line:?}")))?;

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut keep_alive = true; // HTTP/1.1 default
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k.eq_ignore_ascii_case("Content-Length") {
                content_length = v.parse().ok();
            } else if k.eq_ignore_ascii_case("Transfer-Encoding") && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else if k.eq_ignore_ascii_case("Connection") && v.eq_ignore_ascii_case("close") {
                keep_alive = false;
            }
            headers.push((k, v));
        }
    }
    Ok(Some((sep + 4, Head { status, headers, content_length, chunked, keep_alive })))
}

/// Try to parse a complete response from the bytes seen so far. Returns
/// `Some((status, headers, body, keep_alive))` once the whole message is in,
/// else `None` to recv more. `head_request` suppresses the body (HEAD).
fn try_parse(
    resp: &[u8],
    head_request: bool,
) -> Result<Option<(u16, Vec<(String, String)>, Vec<u8>, bool)>> {
    let Some((body_start, h)) = parse_head(resp)? else { return Ok(None) };
    let raw_body = &resp[body_start..];

    if head_request || h.status == 204 || h.status == 304 {
        return Ok(Some((h.status, h.headers, Vec::new(), h.keep_alive)));
    }
    if h.chunked {
        return match dechunk_complete(raw_body)? {
            Some(body) => Ok(Some((h.status, h.headers, body, h.keep_alive))),
            None => Ok(None),
        };
    }
    match h.content_length {
        Some(len) if raw_body.len() >= len => {
            Ok(Some((h.status, h.headers, raw_body[..len].to_vec(), h.keep_alive)))
        }
        Some(_) => Ok(None),       // more body to come
        None => Ok(None),          // no length, not chunked → close-delimited; wait for EOF
    }
}

/// Parse a close-delimited response at EOF (no Content-Length / not chunked).
fn try_parse_eof(
    resp: &[u8],
    head_request: bool,
) -> Result<Option<(u16, Vec<(String, String)>, Vec<u8>)>> {
    let Some((body_start, h)) = parse_head(resp)? else { return Ok(None) };
    let body = if head_request {
        Vec::new()
    } else if h.chunked {
        dechunk_complete(&resp[body_start..])?.unwrap_or_default()
    } else {
        resp[body_start..].to_vec()
    };
    Ok(Some((h.status, h.headers, body)))
}

fn find_crlfcrlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Decode a `Transfer-Encoding: chunked` body. Returns `None` if the terminating
/// `0\r\n\r\n` chunk hasn't fully arrived yet.
fn dechunk_complete(mut b: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        let Some(nl) = b.windows(2).position(|w| w == b"\r\n") else { return Ok(None) };
        let size_str = String::from_utf8_lossy(&b[..nl]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|e| err(format!("chunk size {size_hex:?}: {e}")))?;
        b = &b[nl + 2..];
        if size == 0 {
            return Ok(Some(out)); // final chunk seen
        }
        if b.len() < size + 2 {
            return Ok(None); // chunk data (+ trailing CRLF) not all here yet
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..]; // skip data + trailing CRLF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(method: &str, url: &str, body: &[u8]) -> SignedReq {
        SignedReq {
            method: method.to_string(),
            url: url.to_string(),
            headers: vec![("x-amz-date".to_string(), "20240101T000000Z".to_string())],
            body: body.to_vec(),
        }
    }

    #[test]
    fn serialize_request_line_and_headers() {
        let req = signed("GET", "http://localhost:9000/warehouse/wh/x", b"");
        let raw = serialize_request("localhost:9000", &req);
        let s = String::from_utf8(raw).unwrap();
        assert!(s.starts_with("GET /warehouse/wh/x HTTP/1.1\r\n"), "{s:?}");
        assert!(s.contains("Host: localhost:9000\r\n"));
        assert!(s.contains("Content-Length: 0\r\n"));
        // keep-alive: no Connection: close header.
        assert!(!s.contains("Connection: close"));
        assert!(s.contains("x-amz-date: 20240101T000000Z\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn serialize_query_preserved() {
        let req = signed("GET", "http://localhost:9000/warehouse?list-type=2&prefix=wh", b"");
        let raw = serialize_request("localhost:9000", &req);
        let s = String::from_utf8(raw).unwrap();
        assert!(s.starts_with("GET /warehouse?list-type=2&prefix=wh HTTP/1.1\r\n"), "{s:?}");
    }

    #[test]
    fn serialize_put_body() {
        let req = signed("PUT", "http://localhost:9000/b/k", b"hello");
        let raw = serialize_request("localhost:9000", &req);
        let s = String::from_utf8(raw).unwrap();
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn parse_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"x\"\r\n\r\nhello".to_vec();
        let (status, headers, body, ka) = try_parse(&raw, false).unwrap().unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
        assert!(ka, "keep-alive default");
        assert!(headers.iter().any(|(k, v)| k == "ETag" && v == "\"x\""));
    }

    #[test]
    fn parse_waits_for_short_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".to_vec();
        assert!(try_parse(&raw, false).unwrap().is_none(), "should wait for more body");
        let raw = b"HTTP/1.1 200 OK\r\nContent-Len".to_vec();
        assert!(try_parse(&raw, false).unwrap().is_none(), "should wait for full header");
    }

    #[test]
    fn head_has_no_body_despite_content_length() {
        // HEAD: Content-Length advertised, but no body bytes follow.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n".to_vec();
        let (status, _, body, _) = try_parse(&raw, true).unwrap().unwrap();
        assert_eq!(status, 200);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (status, _, body, _) = try_parse(&raw, true).unwrap().unwrap();
        assert_eq!(status, 404);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_204_no_body() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n".to_vec();
        let (status, _, body, ka) = try_parse(&raw, false).unwrap().unwrap();
        assert_eq!(status, 204);
        assert!(body.is_empty());
        assert!(ka);
    }

    #[test]
    fn parse_connection_close() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".to_vec();
        let (_, _, body, ka) = try_parse(&raw, false).unwrap().unwrap();
        assert_eq!(body, b"hi");
        assert!(!ka, "Connection: close must drop keep-alive");
    }

    #[test]
    fn parse_chunked_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
                .to_vec();
        let (status, _, body, _) = try_parse(&raw, false).unwrap().unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"Wikipedia");
    }

    #[test]
    fn parse_chunked_incomplete_waits() {
        // Missing the terminating 0-chunk.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n".to_vec();
        assert!(try_parse(&raw, false).unwrap().is_none());
    }
}
