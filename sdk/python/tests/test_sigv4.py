"""SigV4 vectors, shared verbatim with the Go SDK.

The same constants appear in sdk/go/objectio/sigv4_test.go. Two
implementations of one algorithm drift silently; pinning both to the same
bytes is what catches it.
"""

from datetime import datetime, timezone

import pytest

from objectio._sigv4 import (
    EMPTY_PAYLOAD_SHA256,
    canonical_query,
    escape,
    escape_path,
    sign_headers,
)

ACCESS_KEY = "AKIAEXAMPLE"
SECRET_KEY = "secretkeyexample"
REGION = "us-east-1"
FIXED = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)

WANT_JSON_POST = (
    "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260914/us-east-1/s3/aws4_request, "
    "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, "
    "Signature=dba80b89d2f2e7762c8e8bb324eb9a214195dd4f46f1c23ded0cba0e3f1de1ff"
)

WANT_AWKWARD_KEY_GET = (
    "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260914/us-east-1/s3/aws4_request, "
    "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
    "Signature=551ff8cbf5e240b59d0db4470dbc862a781c9bb7295112ed76a64b961e863264"
)


def test_sign_json_post_matches_the_go_sdk():
    headers = sign_headers(
        method="POST",
        host="s3.example.com",
        path="/_admin/buckets",
        query=None,
        body=b'{"name":"ws-1","tenant":"platform"}',
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        region=REGION,
        content_type="application/json",
        now=FIXED,
    )
    assert headers["Authorization"] == WANT_JSON_POST
    assert headers["X-Amz-Date"] == "20260914T120000Z"


def test_sign_path_with_space_and_hash_matches_the_go_sdk():
    # The canonicalisation trap: the path signed and the path sent must be the
    # same spelling, or the server answers SignatureDoesNotMatch.
    headers = sign_headers(
        method="GET",
        host="s3.example.com",
        path="/_admin/buckets/b/objects/q1 final#draft.txt",
        query=None,
        body=b"",
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        region=REGION,
        now=FIXED,
    )
    assert headers["Authorization"] == WANT_AWKWARD_KEY_GET


@pytest.mark.parametrize(
    "raw,want",
    [
        ("/_admin/buckets", "/_admin/buckets"),
        ("/a/b c", "/a/b%20c"),
        ("/a/b#c", "/a/b%23c"),
        ("/a/b+c", "/a/b%2Bc"),
        ("/a/~tilde", "/a/~tilde"),
        ("/_admin/buckets/b/objects/x/y/z.json", "/_admin/buckets/b/objects/x/y/z.json"),
    ],
)
def test_escape_path_keeps_separators(raw, want):
    assert escape_path(raw) == want


def test_escape_uses_percent20_not_plus():
    assert escape("a b") == "a%20b"


def test_empty_body_uses_the_known_hash():
    headers = sign_headers(
        method="GET",
        host="s3.example.com",
        path="/_admin/users",
        query=None,
        body=b"",
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        region=REGION,
        now=FIXED,
    )
    assert headers["X-Amz-Content-Sha256"] == EMPTY_PAYLOAD_SHA256


def test_canonical_query_sorts_and_escapes():
    assert canonical_query({"b": "2", "a": "1", "c": "x y"}) == "a=1&b=2&c=x%20y"
    assert canonical_query(None) == ""


def test_non_ascii_is_utf8_percent_encoded():
    # A workspace named in a non-Latin script must still sign.
    assert escape("é") == "%C3%A9"
