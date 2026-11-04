//! Thin HTTP layer over `rsurl` (pure-Rust HTTP/1.1, HTTP/2 and TLS).

use std::time::Duration;

use crate::error::{Error, Result};

fn request(url: &str) -> Result<rsurl::Request> {
    Ok(rsurl::Request::get(url)?
        .header("User-Agent", concat!("apkg/", env!("CARGO_PKG_VERSION")))
        // We verify every byte ourselves; keep the wire format raw so byte
        // ranges map 1:1 onto the file.
        .decompress(false)
        .header("Accept-Encoding", "identity")
        .follow_redirects(true)
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Some(Duration::from_secs(120))))
}

/// GET a URL; returns the status code and body.
pub fn get(url: &str) -> Result<(u16, Vec<u8>)> {
    let r = request(url)?.send()?;
    Ok((r.status, r.body))
}

/// GET a URL and require `200 OK`.
pub fn get_ok(url: &str) -> Result<Vec<u8>> {
    let (status, body) = get(url)?;
    if status != 200 {
        return Err(Error::Http(format!("GET {url}: status {status}")));
    }
    Ok(body)
}

/// Fetch `len` bytes at `offset` with a `Range` request.
pub fn get_range(url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let r = request(url)?
        .header("Range", &format!("bytes={}-{}", offset, offset + len - 1))
        .send()?;
    let body = match r.status {
        206 => r.body,
        // server ignored the range: slice the full body
        200 => {
            let start =
                usize::try_from(offset).map_err(|_| Error::Http("range too large".into()))?;
            r.body.get(start..).map(|b| b.to_vec()).unwrap_or_default()
        }
        s => {
            return Err(Error::Http(format!(
                "GET {url} (range {offset}+{len}): status {s}"
            )));
        }
    };
    if (body.len() as u64) < len {
        return Err(Error::Http(format!(
            "GET {url}: short range response ({} < {len})",
            body.len()
        )));
    }
    let mut body = body;
    body.truncate(len as usize);
    Ok(body)
}

/// Percent-encode the characters of a repository path that S3 mangles.
pub fn escape_path(p: &str) -> String {
    p.replace('+', "%2B")
}
