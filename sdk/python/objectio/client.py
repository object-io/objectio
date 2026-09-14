"""Client for the ObjectIO management API (the ``/_admin/*`` surface)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from ._sigv4 import canonical_query, escape_path, sign_headers
from .errors import APIError

DEFAULT_REGION = "us-east-1"
DEFAULT_TIMEOUT = 30.0
# Cap what an error body can cost us; a misrouted request can return a page.
_MAX_BODY = 1 << 20


@dataclass(frozen=True)
class User:
    user_id: str
    display_name: str = ""
    arn: str = ""
    status: str = ""
    created_at: int = 0
    email: str = ""
    tenant: str = ""


@dataclass(frozen=True)
class AccessKey:
    access_key_id: str
    #: Returned only by :meth:`Client.create_access_key` — never readable
    #: again, so persist it at once or lose it.
    secret_access_key: str = ""
    user_id: str = ""
    status: str = ""
    created_at: int = 0
    #: ``"s3://bucket/"`` or ``"s3://bucket/prefix/"``; empty means unscoped.
    scope: str = ""
    #: ``"READ"`` or ``"READ_WRITE"`` as the server reports it.
    operation: str = ""

    @property
    def scoped(self) -> bool:
        """Whether the key is confined to a bucket or prefix.

        A scoped key is refused by this management API — that is what stops a
        credential handed to a workload from minting itself a wider one.
        """
        return bool(self.scope)


@dataclass(frozen=True)
class Bucket:
    name: str
    created_at: int = 0
    #: Creator's ``user_id``. With no policy attached ObjectIO authorizes on
    #: ownership alone, so this decides who reaches the bucket by default.
    owner: str = ""
    versioning: int = 0
    pool: str = ""
    tenant: str = ""


@dataclass(frozen=True)
class Workspace:
    """A bucket and the one credential confined to it."""

    bucket: str
    access_key_id: str
    secret_access_key: str
    scope: str = ""
    tenant: str = ""
    read_only: bool = False

    def boto3_kwargs(self, endpoint_url: str, region: str = DEFAULT_REGION) -> dict:
        """Keyword arguments for ``boto3.client("s3", **ws.boto3_kwargs(...))``.

        This package does no data operations; this is the handoff to the S3
        client that does.
        """
        return {
            "endpoint_url": endpoint_url,
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "region_name": region,
        }


def _only_known(cls, payload: dict[str, Any]):
    """Build a dataclass from a payload, ignoring fields it does not declare.

    The management API gains fields over time; a client that raises on an
    unexpected one turns a server upgrade into an outage.
    """
    known = set(cls.__dataclass_fields__)
    return cls(**{k: v for k, v in payload.items() if k in known})


@dataclass
class Client:
    """Talks to the ObjectIO management API.

    ``access_key``/``secret_key`` must be an **unscoped** credential: a key
    carrying a bucket or prefix scope is refused here by design.
    """

    endpoint: str
    access_key: str
    secret_key: str
    region: str = DEFAULT_REGION
    timeout: float = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if not self.endpoint:
            raise ValueError("endpoint is required")
        if not self.access_key or not self.secret_key:
            raise ValueError("access_key and secret_key are required")
        self.endpoint = self.endpoint.rstrip("/")

    # -- plumbing ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        query: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> Any:
        payload = raw_body if raw_body is not None else (
            json.dumps(body).encode("utf-8") if body is not None else b""
        )
        content_type = "application/json" if payload else None

        parsed = urllib.parse.urlparse(self.endpoint)
        host = parsed.netloc
        url = self.endpoint + escape_path(path)
        if query:
            url += "?" + canonical_query(query)

        headers = sign_headers(
            method=method,
            host=host,
            path=path,
            query=query,
            body=payload,
            access_key=self.access_key,
            secret_key=self.secret_key,
            region=self.region,
            content_type=content_type,
        )

        req = urllib.request.Request(
            url, data=payload or None, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(_MAX_BODY)
        except urllib.error.HTTPError as exc:
            detail = exc.read(_MAX_BODY).decode("utf-8", "replace").strip()
            raise APIError(exc.code, method, path, detail) from None

        if not raw.strip():
            return None
        return json.loads(raw)

    # -- tenants ----------------------------------------------------------

    def create_tenant(self, name: str, **fields: Any) -> dict:
        """Create a tenant. System admin only."""
        return self._request("POST", "/_admin/tenants", body={"name": name, **fields})

    def get_tenant(self, name: str) -> dict:
        return self._request("GET", f"/_admin/tenants/{name}")

    def list_tenants(self) -> list[dict]:
        out = self._request("GET", "/_admin/tenants")
        return out if isinstance(out, list) else (out or {}).get("tenants", [])

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

    def list_users(self) -> list[User]:
        """Users the caller can see: all of them for the system admin, only
        its own tenant's for a tenant admin."""
        out = self._request("GET", "/_admin/users") or {}
        return [_only_known(User, u) for u in out.get("users", [])]

    def delete_user(self, user_id: str) -> None:
        self._request("DELETE", f"/_admin/users/{user_id}")

    # -- access keys ------------------------------------------------------

    def create_access_key(
        self, user_id: str, *, scope: str = "", read_only: bool = False
    ) -> AccessKey:
        """Mint a key. ``scope`` confines it, e.g. ``"s3://ws-1/"``.

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
        ``{"AWS": [...]}`` is accepted as a synonym."""
        self._request(
            "PUT",
            f"/_admin/buckets/{bucket}/policy",
            raw_body=json.dumps(policy).encode("utf-8"),
        )

    def delete_bucket_policy(self, bucket: str) -> None:
        self._request("DELETE", f"/_admin/buckets/{bucket}/policy")

    # -- workspaces -------------------------------------------------------

    def provision_workspace(
        self,
        bucket: str,
        provisioner_user_id: str,
        *,
        tenant: str = "",
        prefix: str = "",
        read_only: bool = False,
    ) -> Workspace:
        """Create the bucket and mint a credential confined to it.

        Two calls, no bucket policy and no extra user: the provisioner owns
        the bucket it just created, so ownership already grants access, and
        the scope narrows that ownership to this one bucket.

        The credential cannot reach another workspace's bucket and cannot be
        used against this management API at all, so it is safe to hand to a
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
        return Workspace(
            bucket=bucket,
            tenant=tenant,
            access_key_id=key.access_key_id,
            secret_access_key=key.secret_access_key,
            scope=key.scope,
            read_only=read_only,
        )

    def deprovision_workspace(self, provisioner_user_id: str, bucket: str) -> None:
        """Revoke every key scoped to the bucket, then delete it.

        The bucket must already be empty — this does not delete objects,
        deliberately: losing a workspace's data should take more than one call.
        """
        want = f"s3://{bucket}/"
        for key in self.list_access_keys(provisioner_user_id):
            if key.scope.startswith(want):
                self.delete_access_key(key.access_key_id)
        self.delete_bucket(bucket)

    def rotate_workspace_key(
        self, provisioner_user_id: str, bucket: str, *, read_only: bool = False
    ) -> Workspace:
        """Mint a fresh credential for a workspace. The old one keeps working
        until deleted, so a rollout can overlap."""
        key = self.create_access_key(
            provisioner_user_id, scope=f"s3://{bucket}/", read_only=read_only
        )
        return Workspace(
            bucket=bucket,
            access_key_id=key.access_key_id,
            secret_access_key=key.secret_access_key,
            scope=key.scope,
            read_only=read_only,
        )
