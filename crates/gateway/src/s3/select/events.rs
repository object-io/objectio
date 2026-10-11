//! The response's event stream (`application/vnd.amazon.eventstream`).
//!
//! Each message: total length and headers length (u32, big-endian), a
//! CRC32 of those 8 bytes (the prelude), the headers, the payload, and a
//! CRC32 of everything before it. A header is its name's length (u8), the
//! name, its type (7, a string), the value's length (u16) and the value.
//!
//! S3 Select sends `Records` (the output), `Cont` (keep-alive), `Progress`
//! (when asked), `Stats` and `End`; or an error message (`:message-type`
//! `error`) in their place when the query fails after the response began.

fn header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(7);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn message(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    for (k, v) in headers {
        header(&mut h, k, v);
    }
    let total = 12 + h.len() + payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&(h.len() as u32).to_be_bytes());
    let prelude_crc = crc32fast::hash(&out);
    out.extend_from_slice(&prelude_crc.to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(payload);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

fn event(kind: &str, content_type: Option<&str>, payload: &[u8]) -> Vec<u8> {
    let mut headers = vec![(":event-type", kind)];
    if let Some(ct) = content_type {
        headers.push((":content-type", ct));
    }
    headers.push((":message-type", "event"));
    message(&headers, payload)
}

pub fn records(payload: &[u8]) -> Vec<u8> {
    event("Records", Some("application/octet-stream"), payload)
}

pub fn cont() -> Vec<u8> {
    event("Cont", None, b"")
}

pub fn end() -> Vec<u8> {
    event("End", None, b"")
}

/// Byte counts of a `Stats` or `Progress` event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Bytes of the object read (compressed, as stored).
    pub scanned: u64,
    /// Bytes after decompression.
    pub processed: u64,
    /// Bytes of records sent.
    pub returned: u64,
}

fn counts_xml(root: &str, c: Counts) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{root} xmlns=\"\"><BytesScanned>{}</BytesScanned><BytesProcessed>{}</BytesProcessed><BytesReturned>{}</BytesReturned></{root}>",
        c.scanned, c.processed, c.returned
    )
    .into_bytes()
}

pub fn progress(c: Counts) -> Vec<u8> {
    event("Progress", Some("text/xml"), &counts_xml("Progress", c))
}

pub fn stats(c: Counts) -> Vec<u8> {
    event("Stats", Some("text/xml"), &counts_xml("Stats", c))
}

pub fn error(code: &str, text: &str) -> Vec<u8> {
    message(
        &[
            (":error-code", code),
            (":error-message", text),
            (":message-type", "error"),
        ],
        b"",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode one message: (headers, payload), checking both CRCs.
    pub(crate) fn decode(m: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
        let total = u32::from_be_bytes(m[0..4].try_into().unwrap()) as usize;
        let hlen = u32::from_be_bytes(m[4..8].try_into().unwrap()) as usize;
        assert_eq!(total, m.len());
        assert_eq!(
            u32::from_be_bytes(m[8..12].try_into().unwrap()),
            crc32fast::hash(&m[..8])
        );
        assert_eq!(
            u32::from_be_bytes(m[total - 4..].try_into().unwrap()),
            crc32fast::hash(&m[..total - 4])
        );
        let mut headers = Vec::new();
        let mut i = 12;
        while i < 12 + hlen {
            let n = m[i] as usize;
            let name = String::from_utf8(m[i + 1..i + 1 + n].to_vec()).unwrap();
            i += 1 + n;
            assert_eq!(m[i], 7);
            let vl = u16::from_be_bytes(m[i + 1..i + 3].try_into().unwrap()) as usize;
            let value = String::from_utf8(m[i + 3..i + 3 + vl].to_vec()).unwrap();
            i += 3 + vl;
            headers.push((name, value));
        }
        (headers, m[12 + hlen..total - 4].to_vec())
    }

    #[test]
    fn records_frame_round_trips() {
        let m = records(b"a,b\n");
        let (h, p) = decode(&m);
        assert_eq!(p, b"a,b\n");
        assert!(h.contains(&(":event-type".into(), "Records".into())));
        assert!(h.contains(&(":message-type".into(), "event".into())));
        assert!(h.contains(&(":content-type".into(), "application/octet-stream".into())));
    }

    #[test]
    fn a_known_end_frame() {
        // The End message AWS sends, byte for byte.
        let m = end();
        assert_eq!(m.len(), 56);
        assert_eq!(
            &m[..12],
            &[0, 0, 0, 56, 0, 0, 0, 40, 0xc1, 0xc6, 0x84, 0xd4]
        );
    }

    #[test]
    fn stats_and_errors() {
        let (h, p) = decode(&stats(Counts {
            scanned: 10,
            processed: 20,
            returned: 3,
        }));
        assert!(h.contains(&(":event-type".into(), "Stats".into())));
        let p = String::from_utf8(p).unwrap();
        assert!(p.contains("<BytesScanned>10</BytesScanned><BytesProcessed>20</BytesProcessed><BytesReturned>3</BytesReturned>"));
        let (h, p) = decode(&error("CastFailed", "no"));
        assert!(p.is_empty());
        assert!(h.contains(&(":message-type".into(), "error".into())));
        assert!(h.contains(&(":error-code".into(), "CastFailed".into())));
    }
}
