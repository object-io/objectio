"""Typed views of what the management API returns.

The IAM objects — users, keys, tenants, policies, groups, roles — get
dataclasses because callers branch on their fields. The large operational
shapes (cluster info, nodes, topology, usage, pools, metrics) are returned as
plain ``dict``s: they are read by people and dashboards rather than by code,
and they change faster than a client release cadence could track.

Every dataclass is built with :func:`_only_known`, so a field the server adds
later is ignored rather than turning an upgrade into a ``TypeError``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DEFAULT_REGION = "us-east-1"


def _only_known(cls, payload: Optional[Dict[str, Any]]):
    """Build a dataclass from a payload, ignoring fields it does not declare.

    The management API gains fields over time; a client that raises on an
    unexpected one turns a server upgrade into an outage.
    """
    known = set(cls.__dataclass_fields__)
    return cls(**{k: v for k, v in (payload or {}).items() if k in known})


# -- users and keys -------------------------------------------------------

# Older gateways report a user's or key's status in lists as the bare enum
# number ("0"); current ones spell it out ("active") everywhere. Normalised
# on the way in so a caller compares against one spelling.
_USER_STATUS = {"0": "active", "1": "suspended", "2": "deleted"}
_KEY_STATUS = {"0": "active", "1": "inactive"}


@dataclass(frozen=True)
class User:
    user_id: str
    display_name: str = ""
    arn: str = ""
    #: ``"active"`` or ``"suspended"``. A suspended user's every key is
    #: refused (within the gateways' ~15 s credential cache); nothing is
    #: deleted, so :meth:`Client.activate_user` restores it exactly.
    status: str = ""
    created_at: int = 0
    email: str = ""
    tenant: str = ""

    def __post_init__(self) -> None:
        status = str(self.status)
        object.__setattr__(self, "status", _USER_STATUS.get(status, status))


@dataclass(frozen=True)
class AccessKey:
    access_key_id: str
    #: Returned only by :meth:`Client.create_access_key` — never readable
    #: again, so persist it at once or lose it.
    secret_access_key: str = ""
    user_id: str = ""
    #: ``"active"`` or ``"inactive"``.
    status: str = ""
    created_at: int = 0
    #: ``"s3://bucket/"`` or ``"s3://bucket/prefix/"``; empty means unscoped.
    scope: str = ""
    #: ``"READ"`` or ``"READ_WRITE"`` as the server reports it.
    operation: str = ""

    def __post_init__(self) -> None:
        status = str(self.status)
        object.__setattr__(self, "status", _KEY_STATUS.get(status, status))

    @property
    def scoped(self) -> bool:
        """Whether the key is confined to a bucket or prefix.

        A scoped key is refused by this management API — that is what stops a
        credential handed to a workload from minting itself a wider one.
        """
        return bool(self.scope)


# -- tenants and buckets --------------------------------------------------


@dataclass(frozen=True)
class Tenant:
    name: str
    display_name: str = ""
    default_pool: str = ""
    allowed_pools: List[str] = field(default_factory=list)
    #: ``0`` means unlimited, for all three quotas.
    quota_bytes: int = 0
    quota_buckets: int = 0
    quota_objects: int = 0
    #: The tenant's administrators, as user ids or ARNs. This is also the
    #: only way to list them — there is no separate route.
    admin_users: List[str] = field(default_factory=list)
    #: Name of the OIDC provider bound to the tenant (usually
    #: :func:`tenant_oidc_provider_name`), or empty.
    oidc_provider: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    created_at: int = 0
    updated_at: int = 0
    #: ``{"mode": …, "scope": …}`` or ``None`` to inherit the cluster's.
    dedup: Optional[Dict[str, Any]] = None


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
class BucketAccess:
    """A bucket and the one credential confined to it."""

    bucket: str
    access_key_id: str
    secret_key: str
    scope: str = ""
    tenant: str = ""
    read_only: bool = False

    def boto3_kwargs(self, endpoint_url: str, region: str = DEFAULT_REGION) -> dict:
        """Keyword arguments for ``boto3.client("s3", **access.boto3_kwargs(...))``.

        This package does no data operations; this is the handoff to the S3
        client that does.
        """
        return {
            "endpoint_url": endpoint_url,
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_key,
            "region_name": region,
        }


# -- IAM ------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """A named IAM policy.

    ``tenant`` empty means a system policy. A system policy marked ``shared``
    is a catalogue entry: tenant admins may attach it but not change it.
    """

    name: str
    tenant: str = ""
    shared: bool = False
    #: The policy document, parsed.
    policy: Dict[str, Any] = field(default_factory=dict)
    created_at: int = 0
    updated_at: int = 0


@dataclass(frozen=True)
class Group:
    group_id: str
    group_name: str = ""
    arn: str = ""
    tenant: str = ""
    member_user_ids: List[str] = field(default_factory=list)
    created_at: int = 0


@dataclass(frozen=True)
class Role:
    """A role that STS ``AssumeRoleWithWebIdentity`` can hand out.

    The ``arn`` is what a caller passes as ``RoleArn``.
    """

    name: str
    arn: str = ""
    tenant: str = ""
    description: str = ""
    #: Who may assume the role, parsed. Conditions use the token's claims as
    #: ``<issuer>:sub``, ``<issuer>:aud``, ``<issuer>:groups`` …
    trust_policy: Optional[Dict[str, Any]] = None
    #: ``0`` means the server default (one hour).
    max_session_seconds: int = 0
    created_at: int = 0
    updated_at: int = 0
    #: Filled by :meth:`Client.get_role` only; lists leave it empty.
    attached_policies: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Credentials:
    """Temporary credentials from STS. All three parts are needed: the
    session token is what makes the pair valid."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    #: When the credentials stop working (UTC). ``None`` if the server sent
    #: something unparseable.
    expiration: Optional[datetime] = None
    assumed_role_arn: str = ""

    def boto3_kwargs(self, endpoint_url: str, region: str = DEFAULT_REGION) -> dict:
        """Keyword arguments for ``boto3.client("s3", **creds.boto3_kwargs(...))``."""
        return {
            "endpoint_url": endpoint_url,
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_session_token": self.session_token,
            "region_name": region,
        }


# -- public access block --------------------------------------------------

_S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"

# (python attribute, wire name) — S3's PascalCase flag names are used on
# the wire both in the bucket-level XML and the admin API's JSON.
_PAB_FLAGS = (
    ("block_public_acls", "BlockPublicAcls"),
    ("ignore_public_acls", "IgnorePublicAcls"),
    ("block_public_policy", "BlockPublicPolicy"),
    ("restrict_public_buckets", "RestrictPublicBuckets"),
)


def _local(tag: str) -> str:
    """An XML tag without its namespace."""
    return tag.rsplit("}", 1)[-1]


@dataclass(frozen=True)
class PublicAccessBlock:
    """S3's Block Public Access flags, at the bucket, tenant or cluster level.

    A flag set at *any* level holds for the bucket, so a bucket's own block
    can only add to what its tenant and the cluster already enforce.

    - ``block_public_policy``: a bucket policy that would make the bucket
      public is refused.
    - ``restrict_public_buckets``: a public policy already in place grants
      nothing to anonymous callers or to callers outside the bucket's tenant.
    - ``block_public_acls`` / ``ignore_public_acls``: kept and reported. ACLs
      are owner-enforced in ObjectIO, so both hold by construction.
    """

    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False
    #: Which tenant this was read for; empty for the cluster or a bucket.
    tenant: str = ""
    #: Cluster level only: whether new buckets start with every flag set.
    #: ``None`` when it does not apply.
    new_buckets_blocked: Optional[bool] = None

    @classmethod
    def all_blocked(cls) -> "PublicAccessBlock":
        """Every flag set — what a new bucket starts with by default."""
        return cls(True, True, True, True)

    @classmethod
    def from_json(cls, payload: Optional[Dict[str, Any]]) -> "PublicAccessBlock":
        payload = payload or {}
        nbb = payload.get("new_buckets_blocked")
        return cls(
            **{attr: bool(payload.get(wire, False)) for attr, wire in _PAB_FLAGS},
            tenant=payload.get("tenant", "") or "",
            new_buckets_blocked=nbb if isinstance(nbb, bool) else None,
        )

    def flags_json(self) -> Dict[str, bool]:
        """The four flags under their wire (PascalCase) names."""
        return {wire: bool(getattr(self, attr)) for attr, wire in _PAB_FLAGS}

    @classmethod
    def from_xml(cls, text: str) -> "PublicAccessBlock":
        root = ET.fromstring(text)
        values = {_local(el.tag): (el.text or "").strip().lower() for el in root}
        return cls(**{attr: values.get(wire) == "true" for attr, wire in _PAB_FLAGS})

    def to_xml(self) -> bytes:
        """A ``PublicAccessBlockConfiguration`` document. Every flag is
        written, true or false: an absent flag reads as false server-side,
        and spelling them all out keeps the request unambiguous."""
        flags = "".join(
            f"<{wire}>{'true' if getattr(self, attr) else 'false'}</{wire}>"
            for attr, wire in _PAB_FLAGS
        )
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<PublicAccessBlockConfiguration xmlns="{_S3_NS}">{flags}'
            "</PublicAccessBlockConfiguration>"
        ).encode("utf-8")


# -- config and identity providers ----------------------------------------


@dataclass(frozen=True)
class ConfigEntry:
    key: str
    #: The stored value, parsed from JSON. Secrets (an OIDC provider's
    #: ``client_secret``) come back as ``"********"``.
    value: Any = None
    updated_at: int = 0
    updated_by: str = ""
    version: int = 0


#: Config key prefix under which OIDC providers are stored.
OIDC_CONFIG_PREFIX = "identity/openid/"

#: What the gateway returns in place of a stored client secret.
REDACTED_SECRET = "********"

# Fields the gateway reads from a stored provider config. Anything else in
# the document is kept in ``OIDCProvider.extra`` so a round trip through
# this client does not drop it.
_OIDC_FIELDS = (
    "issuer_url",
    "client_id",
    "client_secret",
    "audience",
    "scopes",
    "claim_name",
    "display_name",
    "system_admin",
    "enabled",
    "tenancy",
    "tenant_admin_role",
    "tenant_quota_bytes",
    "allowed_tids",
)


def tenant_oidc_provider_name(tenant: str) -> str:
    """The provider name reserved for a tenant's own identity provider.

    A tenant admin may create and manage exactly this one (``t-<tenant>``,
    lowercased); the ``t-`` prefix keeps tenant-owned providers from
    colliding with the operator's.
    """
    return f"t-{tenant.lower()}"


@dataclass(frozen=True)
class OIDCProvider:
    """A stored OIDC identity provider (config key ``identity/openid/<name>``).

    Unset fields (``None``) are left out of the stored document, so the
    gateway's defaults apply: ``audience`` defaults to ``client_id``,
    ``scopes`` to ``"openid profile email"``, ``claim_name`` to ``"groups"``,
    ``enabled`` to true.
    """

    name: str = ""
    issuer_url: str = ""
    client_id: str = ""
    #: Write-only: reads return ``"********"``.
    client_secret: Optional[str] = None
    audience: Optional[str] = None
    #: Space-separated, as OAuth writes it — e.g. ``"openid profile email"``.
    scopes: Optional[str] = None
    #: The token claim holding group membership.
    claim_name: Optional[str] = None
    display_name: Optional[str] = None
    #: Whether the provider vouches for system administrators (console
    #: login, STS for system roles). Only the system admin may set it.
    system_admin: Optional[bool] = None
    enabled: Optional[bool] = None
    #: ``"multi"`` for a provider federating many upstream tenants (Entra
    #: ``common``); each gets its own ObjectIO tenant on first login.
    tenancy: Optional[str] = None
    #: Role/group claim value that makes a user an admin of its tenant.
    tenant_admin_role: Optional[str] = None
    #: Quota for a tenant that registers itself through this provider.
    tenant_quota_bytes: Optional[int] = None
    #: Upstream tenant ids allowed to self-register; empty means any.
    allowed_tids: Optional[List[str]] = None
    #: Stored fields this client does not model, kept for round trips.
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_config(cls, name: str, value: Any) -> "OIDCProvider":
        doc = value if isinstance(value, dict) else {}
        known = {k: doc[k] for k in _OIDC_FIELDS if k in doc}
        extra = {k: v for k, v in doc.items() if k not in _OIDC_FIELDS}
        return cls(name=name, extra=extra, **known)

    def to_config(self) -> Dict[str, Any]:
        """The document stored under the provider's config key."""
        doc = dict(self.extra)
        for k in _OIDC_FIELDS:
            v = getattr(self, k)
            if v is not None:
                doc[k] = v
        return doc


# -- KMS and warehouses ---------------------------------------------------


@dataclass(frozen=True)
class KMSKey:
    key_id: str
    arn: str = ""
    description: str = ""
    #: ``"Enabled"``, ``"Disabled"`` or ``"PendingDeletion"``.
    status: str = ""
    created_at: int = 0
    updated_at: int = 0
    created_by: str = ""


@dataclass(frozen=True)
class Warehouse:
    """An Iceberg warehouse and the bucket meta provisioned behind it."""

    name: str
    bucket: str = ""
    location: str = ""
    tenant: str = ""
    created_at: int = 0
    properties: Dict[str, str] = field(default_factory=dict)


def parse_expiration(text: str) -> Optional[datetime]:
    """An STS ``Expiration`` (``2026-10-02T12:00:00Z``) as an aware datetime."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
