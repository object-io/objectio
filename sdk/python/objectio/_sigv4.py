"""AWS SigV4 for the S3 service, on the standard library alone.

Deliberately not botocore: this package is meant to be installable into an
operator or a provisioning job where pulling in the AWS SDK for one signing
function is a large dependency for no gain. The algorithm is stable.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

ALGORITHM = "AWS4-HMAC-SHA256"
TERMINATOR = "aws4_request"
SERVICE = "s3"

# Every request signs its payload hash; S3 wants the header whether or not
# there is a body, and an empty body hashes to this.
EMPTY_PAYLOAD_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)


def escape(value: str) -> str:
    """Percent-encode everything outside the unreserved set.

    ``urllib.parse.quote`` is close but its default safe set and its handling
    of ``~`` have bitten people; spelling it out is shorter than the caveats.
    """
    out = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        if ch in _UNRESERVED:
            out.append(ch)
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def escape_path(path: str) -> str:
    """Encode a path the way SigV4 canonicalises it for S3: each segment
    escaped, the separators left alone, no double encoding.

    The same function builds the URL that is sent and the canonical path that
    is signed. That is the point — a signature mismatch on a key containing a
    space or a ``#`` is almost always those two disagreeing.
    """
    return "/".join(escape(seg) for seg in path.split("/"))


def canonical_query(params: dict[str, str] | None) -> str:
    if not params:
        return ""
    return "&".join(
        f"{escape(k)}={escape(v)}" for k, v in sorted(params.items())
    )


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def sign_headers(
    *,
    method: str,
    host: str,
    path: str,
    query: dict[str, str] | None,
    body: bytes,
    access_key: str,
    secret_key: str,
    region: str,
    content_type: str | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Return the headers that authenticate this request.

    ``path`` must be the *unescaped* path; it is canonicalised here so the
    caller cannot accidentally sign one spelling and send another.
    """
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    amz_date = stamp.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = stamp.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(body).hexdigest() if body else EMPTY_PAYLOAD_SHA256

    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if content_type:
        headers["content-type"] = content_type

    signed_names = sorted(headers)
    canonical_headers = "".join(f"{h}:{headers[h].strip()}\n" for h in signed_names)
    signed_headers = ";".join(signed_names)

    canonical_request = "\n".join(
        [
            method,
            escape_path(path) or "/",
            canonical_query(query),
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    scope = f"{date_stamp}/{region}/{SERVICE}/{TERMINATOR}"
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    key = _hmac(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    key = _hmac(key, region)
    key = _hmac(key, SERVICE)
    key = _hmac(key, TERMINATOR)
    signature = hmac.new(
        key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    out = {
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": (
            f"{ALGORITHM} Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    if content_type:
        out["Content-Type"] = content_type
    return out
