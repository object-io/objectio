"""STS ``AssumeRoleWithWebIdentity``: an OIDC token for temporary S3
credentials of a role.

The call is **unsigned** — a form ``POST /`` on the S3 endpoint, as AWS
SDKs send it — because the token is the proof. So it works from a client
built with only an endpoint: ``Client(endpoint=...)``.
"""

from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET

from .errors import APIError
from .models import Credentials, _local, parse_expiration

STS_VERSION = "2011-06-15"


def parse_assume_role_response(text: str) -> Credentials:
    """Credentials from an ``AssumeRoleWithWebIdentityResponse`` document."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise APIError(200, "POST", "/", f"unreadable STS response: {exc}") from None
    found = {}
    for el in root.iter():
        name = _local(el.tag)
        # <Arn> appears only under <AssumedRoleUser>; the rest only under
        # <Credentials>. Flattening is safe for this document.
        if name in (
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "Expiration",
            "Arn",
        ):
            found[name] = (el.text or "").strip()
    if not found.get("AccessKeyId"):
        raise APIError(200, "POST", "/", f"STS response carries no credentials: {text[:200]}")
    return Credentials(
        access_key_id=found["AccessKeyId"],
        secret_access_key=found.get("SecretAccessKey", ""),
        session_token=found.get("SessionToken", ""),
        expiration=parse_expiration(found.get("Expiration", "")),
        assumed_role_arn=found.get("Arn", ""),
    )


class STSMixin:
    def assume_role_with_web_identity(
        self,
        role_arn: str,
        web_identity_token: str,
        session_name: str,
        duration_seconds: int | None = None,
    ) -> Credentials:
        """Exchange an OIDC token for temporary credentials of a role.

        ``role_arn`` is :attr:`Role.arn` (``arn:obio:iam::<tenant>:role/<name>``;
        ``arn:aws:`` is accepted too). ``session_name`` is 2–64 characters of
        ``[\\w+=,.@-]`` and ends up in the session's ARN, so it shows in audit
        logs. ``duration_seconds`` is 900 up to the role's
        ``max_session_seconds`` (default one hour).

        Unsigned: needs no access key. A refusal raises :class:`APIError`
        whose ``code`` is the STS error code — ``AccessDenied``,
        ``ExpiredTokenException``, ``ValidationError`` … An unknown role is
        refused exactly like a bad token, so role names cannot be probed.
        """
        form = {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": STS_VERSION,
            "RoleArn": role_arn,
            "WebIdentityToken": web_identity_token,
            "RoleSessionName": session_name,
        }
        if duration_seconds is not None:
            form["DurationSeconds"] = str(int(duration_seconds))
        text = self._request(
            "POST",
            "/",
            raw_body=urllib.parse.urlencode(form).encode("utf-8"),
            content_type="application/x-www-form-urlencoded",
            parse="text",
            signed=False,
        )
        return parse_assume_role_response(text)
