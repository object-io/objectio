//! The SigV4 `Authorization` header, parsed.
//!
//! The gateway verifies signatures (`auth_middleware`); this is the parse
//! it shares with anything else that reads the header.

/// The parts of a SigV4 `Authorization` header a verifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuth {
    pub access_key_id: String,
    /// Lower-cased, in the order given.
    pub signed_headers: Vec<String>,
    pub signature: String,
}

/// Parse a SigV4 `Authorization` header:
///
/// ```text
/// AWS4-HMAC-SHA256 Credential=AKID/20261007/us-east-1/s3/aws4_request,
///   SignedHeaders=host;x-amz-date, Signature=<hex>
/// ```
///
/// By hand, not with a regex: it runs on every request (a regex compiled
/// per call was a quarter of a gateway's CPU on small PUTs). `None` when
/// the header is not of that form.
#[must_use]
pub fn parse_authorization(header: &str) -> Option<ParsedAuth> {
    let rest = header.strip_prefix("AWS4-HMAC-SHA256")?;
    // At least one space after the algorithm.
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut parts = rest.split(',').map(str::trim);
    let credential = parts.next()?.strip_prefix("Credential=")?;
    let signed = parts.next()?.strip_prefix("SignedHeaders=")?;
    let signature = parts.next()?.strip_prefix("Signature=")?;
    // The access key is the credential's first part; a scope must follow.
    let (access_key_id, scope) = credential.split_once('/')?;
    // The signature: its leading word characters (letters, digits, `_`).
    let end = signature
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(signature.len());
    let signature = &signature[..end];
    if access_key_id.is_empty() || scope.is_empty() || signed.is_empty() || signature.is_empty() {
        return None;
    }
    Some(ParsedAuth {
        access_key_id: access_key_id.to_string(),
        signed_headers: signed.split(';').map(str::to_lowercase).collect(),
        signature: signature.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authorization_header_parses_without_a_regex() {
        let h = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261007/us-east-1/s3/aws4_request, \
                 SignedHeaders=Host;x-amz-content-sha256;x-amz-date, Signature=fe5f80f77d5fa3be";
        let p = parse_authorization(h).unwrap();
        assert_eq!(p.access_key_id, "AKIDEXAMPLE");
        assert_eq!(
            p.signed_headers,
            ["host", "x-amz-content-sha256", "x-amz-date"]
        );
        assert_eq!(p.signature, "fe5f80f77d5fa3be");
        // No spaces after the commas, several before Credential.
        let tight = "AWS4-HMAC-SHA256   Credential=AK/scope,SignedHeaders=host,Signature=abc";
        assert_eq!(parse_authorization(tight).unwrap().signature, "abc");
        // The signature is its word characters.
        let trailing = "AWS4-HMAC-SHA256 Credential=AK/s, SignedHeaders=host, Signature=abc def";
        assert_eq!(parse_authorization(trailing).unwrap().signature, "abc");
        for bad in [
            "AWS AKID:sig",
            "AWS4-HMAC-SHA256Credential=AK/s, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=AK, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=/s, SignedHeaders=host, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=AK/s, SignedHeaders=host",
            "AWS4-HMAC-SHA256 Credential=AK/s, SignedHeaders=, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=AK/s, SignedHeaders=host, Signature=",
            "AWS4-HMAC-SHA256 SignedHeaders=host, Credential=AK/s, Signature=abc",
        ] {
            assert_eq!(parse_authorization(bad), None, "{bad}");
        }
    }
}
