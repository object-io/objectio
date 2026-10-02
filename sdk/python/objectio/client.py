"""Client for the ObjectIO management API (the ``/_admin/*`` surface).

The :class:`Client` is assembled from mixins, one per area, so each file
stays readable:

- this module: plumbing, configuration, tenants, users, access keys,
  buckets and bucket provisioning;
- :mod:`objectio._iam`: named policies, groups and roles;
- :mod:`objectio._sts`: ``AssumeRoleWithWebIdentity``;
- :mod:`objectio._config`: stored configuration and OIDC providers;
- :mod:`objectio._access`: Block Public Access and per-bucket dedup;
- :mod:`objectio._cluster`: nodes, pools, KMS, warehouses and metrics.
"""

from __future__ import annotations

import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from ._access import AccessMixin
from ._cluster import ClusterMixin
from ._config import ConfigMixin
from ._iam import IAMMixin
from ._sigv4 import canonical_query, escape_path, sign_headers
from ._sts import STSMixin
from .errors import APIError, ObjectIOError
from .models import (
    DEFAULT_REGION,
    AccessKey,
    Bucket,
    BucketAccess,
    Tenant,
    User,
    _only_known,
)

DEFAULT_TIMEOUT = 30.0
# Cap what an error body can cost us; a misrouted request can return a page.
_MAX_BODY = 1 << 20
# Successful bodies can legitimately be large (a metrics range query, a
# placement-group page), so they get a much higher ceiling.
_MAX_OK_BODY = 64 << 20

_XML_CODE = re.compile(rb"<Code>\s*([^<\s]+)\s*</Code>")
_XML_MESSAGE = re.compile(rb"<Message>(.*?)</Message>", re.S)


def _error_message(body: bytes) -> str:
    """The human part of an error body: an XML error's ``<Message>``, a
    JSON error's ``"error"``, or else the body as text."""
    m = _XML_MESSAGE.search(body)
    if m:
        return html.unescape(m.group(1).decode("utf-8", "replace")).strip()
    text = body.decode("utf-8", "replace").strip()
    if text.startswith("{"):
        try:
            err = json.loads(text).get("error")
        except (ValueError, AttributeError):
            err = None
        if isinstance(err, str) and err:
            return err
    return text


def _error_code(body: bytes) -> str:
    """The ``<Code>`` of an S3/STS XML error document, or ``""``.

    A regex rather than a parser: an error body may be truncated at
    ``_MAX_BODY`` or not be XML at all, and the code is all that is wanted.
    """
    m = _XML_CODE.search(body)
    return m.group(1).decode("utf-8", "replace") if m else ""


#: Environment variables read by :meth:`Client.from_env`.
ENV_ENDPOINT = "OBJECTIO_ENDPOINT"
ENV_URL = "OBJECTIO_URL"
ENV_ACCESS_KEY = "OBJECTIO_ACCESS_KEY"
ENV_ACCESS_KEY_FILE = "OBJECTIO_ACCESS_KEY_FILE"
ENV_SECRET_KEY = "OBJECTIO_SECRET_KEY"
ENV_SECRET_KEY_FILE = "OBJECTIO_SECRET_KEY_FILE"
ENV_REGION = "OBJECTIO_REGION"
#: The provisioner's own ``user_id``, which :meth:`Client.provision_bucket`
#: needs. Read it with :func:`provisioner_user_id_from_env`.
ENV_PROVISIONER_USER_ID = "OBJECTIO_PROVISIONER_USER_ID"


def _from_env(file_var: str | None, direct_var: str, *fallbacks: str) -> str:
    """Resolve one setting: a ``*_FILE`` variable first, then the direct name,
    then any fallbacks.

    File contents are stripped. A mounted secret almost always ends in a
    newline, and a trailing ``\\n`` inside a signing key produces a
    SignatureDoesNotMatch that reads like a wrong password.
    """
    if file_var:
        path = os.environ.get(file_var, "")
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
    for name in (direct_var, *fallbacks):
        value = os.environ.get(name, "")
        if value:
            return value.strip()
    return ""


def provisioner_user_id_from_env() -> str:
    """The provisioner's ``user_id`` from the environment, or ``""``."""
    return os.environ.get(ENV_PROVISIONER_USER_ID, "").strip()


@dataclass
class Client(IAMMixin, STSMixin, ConfigMixin, AccessMixin, ClusterMixin):
    """Talks to the ObjectIO management API.

    ``access_key``/``secret_key`` must be an **unscoped** credential: a key
    carrying a bucket or prefix scope is refused here by design.

    Both may be omitted — ``Client(endpoint=...)`` — for a client that only
    calls :meth:`assume_role_with_web_identity`, which is unsigned (the web
    identity token is the proof). Every other method then raises
    :class:`ObjectIOError` before sending anything.
    """

    endpoint: str
    access_key: str = ""
    secret_key: str = ""
    region: str = DEFAULT_REGION
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls) -> "Client":
        """Build a client from the environment.

        ::

            OBJECTIO_ENDPOINT   | OBJECTIO_URL                           (required)
            OBJECTIO_ACCESS_KEY | OBJECTIO_ACCESS_KEY_FILE | AWS_ACCESS_KEY_ID
            OBJECTIO_SECRET_KEY | OBJECTIO_SECRET_KEY_FILE | AWS_SECRET_ACCESS_KEY
            OBJECTIO_REGION     | AWS_REGION | AWS_DEFAULT_REGION   (default us-east-1)

        The AWS names are accepted so one set of variables configures both this
        client and the boto3 client beside it.

        Prefer the ``*_FILE`` forms in Kubernetes: a secret in the environment
        is readable from ``/proc``, lands in crash dumps, and shows up in
        ``kubectl describe pod`` when it was set inline rather than from a
        ``secretRef``.

        The credential must be unscoped — a key confined to a bucket is
        refused on the management API.
        """
        endpoint = _from_env(None, ENV_ENDPOINT, ENV_URL)
        if not endpoint:
            raise ValueError(f"{ENV_ENDPOINT} (or {ENV_URL}) is not set")

        access_key = _from_env(ENV_ACCESS_KEY_FILE, ENV_ACCESS_KEY, "AWS_ACCESS_KEY_ID")
        if not access_key:
            raise ValueError(
                f"{ENV_ACCESS_KEY}, {ENV_ACCESS_KEY_FILE} or AWS_ACCESS_KEY_ID is not set"
            )

        secret_key = _from_env(ENV_SECRET_KEY_FILE, ENV_SECRET_KEY, "AWS_SECRET_ACCESS_KEY")
        if not secret_key:
            raise ValueError(
                f"{ENV_SECRET_KEY}, {ENV_SECRET_KEY_FILE} or AWS_SECRET_ACCESS_KEY is not set"
            )

        region = _from_env(None, ENV_REGION, "AWS_REGION", "AWS_DEFAULT_REGION")
        return cls(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            region=region or DEFAULT_REGION,
        )

    def __post_init__(self) -> None:
        if not self.endpoint:
            raise ValueError("endpoint is required")
        # Half a credential is a configuration mistake, not an unsigned
        # client; say so now rather than at the first signed call.
        if bool(self.access_key) != bool(self.secret_key):
            raise ValueError("access_key and secret_key must be given together")
        self.endpoint = self.endpoint.rstrip("/")

    @property
    def has_credentials(self) -> bool:
        """Whether this client can sign — false for an STS-only client."""
        return bool(self.access_key and self.secret_key)

    # -- plumbing ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        query: dict[str, str] | None = None,
        raw_body: bytes | None = None,
        content_type: str | None = None,
        parse: str = "json",
        signed: bool = True,
    ) -> Any:
        """Send one request and return the decoded answer.

        ``parse`` is ``"json"`` (the admin API; an empty body is ``None``) or
        ``"text"`` (the S3 and STS XML answers). ``signed=False`` sends no
        ``Authorization`` at all — used only for STS.
        """
        if signed and not self.has_credentials:
            raise ObjectIOError(
                f"{method} {path} needs credentials; this client was built "
                "without access_key/secret_key (only "
                "assume_role_with_web_identity works unsigned)"
            )

        payload = raw_body if raw_body is not None else (
            json.dumps(body).encode("utf-8") if body is not None else b""
        )
        if payload and content_type is None:
            content_type = "application/json"

        parsed = urllib.parse.urlparse(self.endpoint)
        host = parsed.netloc
        url = self.endpoint + escape_path(path)
        if query:
            url += "?" + canonical_query(query)

        if signed:
            headers = sign_headers(
                method=method,
                host=host,
                path=path,
                query=query,
                body=payload,
                access_key=self.access_key,
                secret_key=self.secret_key,
                region=self.region,
                content_type=content_type if payload else None,
            )
        else:
            headers = {"Content-Type": content_type} if payload and content_type else {}

        req = urllib.request.Request(
            url, data=payload or None, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(_MAX_OK_BODY)
        except urllib.error.HTTPError as exc:
            raw_err = exc.read(_MAX_BODY)
            detail = _error_message(raw_err)
            raise APIError(
                exc.code, method, path, detail, code=_error_code(raw_err)
            ) from None

        if parse == "text":
            return raw.decode("utf-8", "replace")
        if not raw.strip():
            return None
        return json.loads(raw)

    @staticmethod
    def _tenant_query(tenant: str) -> dict[str, str] | None:
        """``?tenant=`` when one is named.

        Omitted rather than sent empty on purpose: for the system admin
        several list endpoints read a *present but empty* ``tenant`` as
        "system scope only", while an absent one means "everything".
        """
        return {"tenant": tenant} if tenant else None

    # -- tenants ----------------------------------------------------------

    def create_tenant(self, name: str, **fields: Any) -> Tenant:
        """Create a tenant. System admin only.

        ``fields`` are the tenant's other settings by their wire names —
        ``display_name``, ``quota_bytes``, ``default_pool``, ``labels`` …
        (see :class:`~objectio.Tenant`).
        """
        out = self._request("POST", "/_admin/tenants", body={"name": name, **fields})
        return _only_known(Tenant, out)

    def get_tenant(self, name: str) -> Tenant:
        """A tenant. A tenant admin may read its own; anyone else needs the
        system admin."""
        return _only_known(Tenant, self._request("GET", f"/_admin/tenants/{name}"))

    def list_tenants(self) -> list[Tenant]:
        """Every tenant for the system admin; a tenant user sees only its own."""
        out = self._request("GET", "/_admin/tenants")
        rows = out if isinstance(out, list) else (out or {}).get("tenants", [])
        return [_only_known(Tenant, t) for t in rows]

    def update_tenant(self, name: str, **fields: Any) -> Tenant:
        """Change some of a tenant's settings. System admin only.

        The server's ``PUT`` replaces the whole tenant — a field left out is
        reset to its default, which for ``admin_users`` means losing every
        tenant admin. So this reads the tenant, applies ``fields`` on top and
        writes the result back. Two concurrent updates can still race; the
        last one wins.
        """
        current = self._request("GET", f"/_admin/tenants/{name}") or {}
        merged = {**current, **fields, "name": name}
        out = self._request("PUT", f"/_admin/tenants/{name}", body=merged)
        return _only_known(Tenant, out)

    def delete_tenant(self, name: str) -> None:
        self._request("DELETE", f"/_admin/tenants/{name}")

    def add_tenant_admin(self, tenant: str, user_id: str) -> None:
        """Let a user administer its own tenant — create buckets, users and
        access keys inside it, and nowhere else. This is what turns a plain
        user into a provisioner."""
        self._request(
            "POST", f"/_admin/tenants/{tenant}/admins", body={"user_id": user_id}
        )

    def remove_tenant_admin(self, tenant: str, user: str) -> None:
        self._request("DELETE", f"/_admin/tenants/{tenant}/admins/{user}")

    # -- users ------------------------------------------------------------

    def create_user(self, display_name: str, tenant: str = "") -> User:
        out = self._request(
            "POST", "/_admin/users", body={"display_name": display_name, "tenant": tenant}
        )
        return _only_known(User, out)

    def get_user(self, user_id: str) -> User:
        return _only_known(User, self._request("GET", f"/_admin/users/{user_id}"))

    def list_users(self) -> list[User]:
        """Users the caller can see: all of them for the system admin, only
        its own tenant's for a tenant admin."""
        out = self._request("GET", "/_admin/users") or {}
        return [_only_known(User, u) for u in out.get("users", [])]

    def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        status: str | None = None,
    ) -> User:
        """Change a user. Fields left as ``None`` are not touched.

        ``status`` is ``"active"`` or ``"suspended"``; see
        :meth:`suspend_user`.
        """
        body: dict[str, Any] = {}
        if display_name is not None:
            body["display_name"] = display_name
        if email is not None:
            body["email"] = email
        if status is not None:
            body["status"] = status
        return _only_known(
            User, self._request("PUT", f"/_admin/users/{user_id}", body=body)
        )

    def suspend_user(self, user_id: str) -> User:
        """Refuse every key the user has, without deleting anything.

        Takes effect within the gateways' credential cache (about 15 s). The
        server refuses to let a caller suspend itself.
        """
        return self.update_user(user_id, status="suspended")

    def activate_user(self, user_id: str) -> User:
        """Undo :meth:`suspend_user`."""
        return self.update_user(user_id, status="active")

    def delete_user(self, user_id: str) -> None:
        self._request("DELETE", f"/_admin/users/{user_id}")

    # -- access keys ------------------------------------------------------

    def create_access_key(
        self, user_id: str, *, scope: str = "", read_only: bool = False
    ) -> AccessKey:
        """Mint a key. ``scope`` confines it, e.g. ``"s3://bucket-1/"``.

        The returned secret is the only copy.
        """
        body: dict[str, Any] = {"operation": "R" if read_only else "RW"}
        if scope:
            body["scope"] = scope
        return _only_known(
            AccessKey, self._request("POST", f"/_admin/users/{user_id}/access-keys", body=body)
        )

    def list_access_keys(self, user_id: str) -> list[AccessKey]:
        out = self._request("GET", f"/_admin/users/{user_id}/access-keys")
        rows = out if isinstance(out, list) else (out or {}).get("access_keys", [])
        return [_only_known(AccessKey, k) for k in rows]

    def update_access_key(self, access_key_id: str, *, status: str) -> AccessKey:
        """Set a key ``"active"`` or ``"inactive"``.

        The answer carries ``access_key_id``, ``user_id`` and ``status`` only.
        """
        out = self._request(
            "PUT", f"/_admin/access-keys/{access_key_id}", body={"status": status}
        )
        return _only_known(AccessKey, out)

    def deactivate_access_key(self, access_key_id: str) -> AccessKey:
        """Stop a key working without deleting it — the reversible half of a
        revocation. Takes effect within the gateways' credential cache (about
        15 s). A caller cannot deactivate the key it is signing with."""
        return self.update_access_key(access_key_id, status="inactive")

    def activate_access_key(self, access_key_id: str) -> AccessKey:
        return self.update_access_key(access_key_id, status="active")

    def delete_access_key(self, access_key_id: str) -> None:
        """Revoke a key. This is the rotation primitive: mint the replacement,
        roll it out, then delete the old one."""
        self._request("DELETE", f"/_admin/access-keys/{access_key_id}")

    # -- buckets ----------------------------------------------------------

    def create_bucket(self, name: str, tenant: str = "") -> None:
        """Create a bucket. The caller becomes its owner, which matters: with
        no policy attached, ownership is what grants access."""
        body = {"name": name}
        if tenant:
            body["tenant"] = tenant
        self._request("POST", "/_admin/buckets", body=body)

    def list_buckets(self) -> list[Bucket]:
        out = self._request("GET", "/_admin/buckets") or {}
        return [_only_known(Bucket, b) for b in out.get("buckets", [])]

    def delete_bucket(self, name: str) -> None:
        self._request("DELETE", f"/_admin/buckets/{name}")

    def set_bucket_owner(self, bucket: str, owner_user_id: str) -> None:
        self._request(
            "PUT", f"/_admin/buckets/{bucket}/owner", body={"owner": owner_user_id}
        )

    def get_bucket_policy(self, bucket: str) -> dict | None:
        """The attached policy, or ``None``.

        No policy does not mean open — ObjectIO then falls back to owner-only.
        """
        out = self._request("GET", f"/_admin/buckets/{bucket}/policy") or {}
        return out.get("policy") if out.get("has_policy") else None

    def put_bucket_policy(self, bucket: str, policy: dict) -> None:
        """Attach a policy. Needed only when an identity other than the owner
        must reach the bucket. Principals are ARNs under ``{"OBIO": [...]}``;
        ``{"AWS": [...]}`` is accepted as a synonym.

        Note: the S3 API's ``PUT /{bucket}?policy`` refuses a policy that
        would make the bucket public while ``block_public_policy`` holds
        (see :meth:`put_bucket_public_access_block`); this admin route does
        not check that yet, so check :meth:`get_bucket_policy_status`
        afterwards if it matters."""
        self._request(
            "PUT",
            f"/_admin/buckets/{bucket}/policy",
            raw_body=json.dumps(policy).encode("utf-8"),
        )

    def delete_bucket_policy(self, bucket: str) -> None:
        self._request("DELETE", f"/_admin/buckets/{bucket}/policy")

    # -- bucket provisioning ----------------------------------------------

    def provision_bucket(
        self,
        bucket: str,
        provisioner_user_id: str,
        *,
        tenant: str = "",
        prefix: str = "",
        read_only: bool = False,
    ) -> BucketAccess:
        """Create the bucket and mint a credential confined to it.

        Two calls, no bucket policy and no extra user: the provisioner owns
        the bucket it just created, so ownership already grants access, and
        the scope narrows that ownership to this one bucket (or ``prefix``
        inside it, which must end in ``/``).

        The credential cannot reach another bucket and cannot be used
        against this management API at all, so it is safe to hand to a
        workload that should only see its own data.
        """
        if prefix and not prefix.endswith("/"):
            raise ValueError(f"prefix {prefix!r} must end in /")

        self.create_bucket(bucket, tenant)
        key = self.create_access_key(
            provisioner_user_id,
            scope=f"s3://{bucket}/{prefix}",
            read_only=read_only,
        )
        return BucketAccess(
            bucket=bucket,
            tenant=tenant,
            access_key_id=key.access_key_id,
            secret_key=key.secret_access_key,
            scope=key.scope,
            read_only=read_only,
        )

    def deprovision_bucket(self, provisioner_user_id: str, bucket: str) -> None:
        """Revoke every key scoped to the bucket, then delete it.

        The bucket must already be empty — this does not delete objects,
        deliberately: losing a bucket's data should take more than one call.
        """
        want = f"s3://{bucket}/"
        for key in self.list_access_keys(provisioner_user_id):
            if key.scope.startswith(want):
                self.delete_access_key(key.access_key_id)
        self.delete_bucket(bucket)

    def rotate_bucket_key(
        self, provisioner_user_id: str, bucket: str, *, read_only: bool = False
    ) -> BucketAccess:
        """Mint a fresh credential for a provisioned bucket. The old one keeps
        working until deleted, so a rollout can overlap."""
        key = self.create_access_key(
            provisioner_user_id, scope=f"s3://{bucket}/", read_only=read_only
        )
        return BucketAccess(
            bucket=bucket,
            access_key_id=key.access_key_id,
            secret_key=key.secret_access_key,
            scope=key.scope,
            read_only=read_only,
        )
