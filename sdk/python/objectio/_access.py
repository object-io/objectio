"""Block Public Access (cluster, tenant and bucket level) and per-bucket
deduplication.

The tenant and cluster blocks are admin API calls with JSON bodies. The
bucket block and policy status are **S3 API** calls (``/{bucket}?publicAccessBlock``,
``?policyStatus``) with XML bodies, exactly as S3 has them; they are signed
the same way, so the same credential works for both.
"""

from __future__ import annotations

import re
from typing import Any

from .errors import APIError
from .models import PublicAccessBlock

_IS_PUBLIC = re.compile(r"<IsPublic>\s*(true|false)\s*</IsPublic>", re.IGNORECASE)


class AccessMixin:
    # -- cluster / tenant block -------------------------------------------

    def get_public_access_block(self, tenant: str = "") -> PublicAccessBlock:
        """The cluster's block (system admin, no ``tenant``) or a tenant's.

        A level with nothing stored reads as all flags false. For the
        cluster, ``new_buckets_blocked`` says whether new buckets start with
        every flag set (true unless turned off).
        """
        out = self._request(
            "GET", "/_admin/public-access-block", query=self._tenant_query(tenant)
        )
        return PublicAccessBlock.from_json(out)

    def put_public_access_block(
        self,
        block: PublicAccessBlock,
        *,
        tenant: str = "",
        new_buckets_blocked: bool | None = None,
    ) -> PublicAccessBlock:
        """Set the cluster's block (no ``tenant``) or a tenant's.

        A flag set here holds for every bucket beneath, whatever the bucket's
        own block says. ``new_buckets_blocked`` is cluster-only; left as
        ``None``, the cluster's current setting is kept.
        """
        body: dict[str, Any] = block.flags_json()
        if new_buckets_blocked is not None:
            if tenant:
                raise ValueError("new_buckets_blocked is a cluster setting; omit tenant")
            body["new_buckets_blocked"] = bool(new_buckets_blocked)
        out = self._request(
            "PUT",
            "/_admin/public-access-block",
            query=self._tenant_query(tenant),
            body=body,
        )
        result = PublicAccessBlock.from_json(out)
        # The PUT answer omits the tenant it applies to; fill it in so the
        # result reads the same as a get.
        if tenant:
            result = PublicAccessBlock(
                result.block_public_acls,
                result.ignore_public_acls,
                result.block_public_policy,
                result.restrict_public_buckets,
                tenant=tenant,
                new_buckets_blocked=None,
            )
        return result

    def delete_public_access_block(self, tenant: str = "") -> None:
        """Remove the cluster's (no ``tenant``) or a tenant's block. For the
        cluster this also restores ``new_buckets_blocked`` to true."""
        self._request(
            "DELETE", "/_admin/public-access-block", query=self._tenant_query(tenant)
        )

    # -- bucket block (S3 API) --------------------------------------------

    def get_bucket_public_access_block(self, bucket: str) -> PublicAccessBlock | None:
        """The bucket's own block, or ``None`` if it has none.

        This is the bucket's setting alone; what actually holds is this
        combined with its tenant's and the cluster's. New buckets start with
        every flag set unless the cluster's ``new_buckets_blocked`` is off.
        """
        try:
            text = self._request(
                "GET", f"/{bucket}", query={"publicAccessBlock": ""}, parse="text"
            )
        except APIError as exc:
            if exc.code == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise
        return PublicAccessBlock.from_xml(text)

    def put_bucket_public_access_block(self, bucket: str, block: PublicAccessBlock) -> None:
        self._request(
            "PUT",
            f"/{bucket}",
            query={"publicAccessBlock": ""},
            raw_body=block.to_xml(),
            content_type="application/xml",
            parse="text",
        )

    def delete_bucket_public_access_block(self, bucket: str) -> None:
        """Remove the bucket's own block. Its tenant's and the cluster's
        still hold."""
        self._request(
            "DELETE", f"/{bucket}", query={"publicAccessBlock": ""}, parse="text"
        )

    def get_bucket_policy_status(self, bucket: str) -> bool:
        """Whether the bucket's policy makes it public.

        A bucket with no policy is not public, so this returns ``False``
        where S3 itself answers ``NoSuchBucketPolicy``. Whether a public
        policy is actually honoured depends on ``restrict_public_buckets``.
        """
        try:
            text = self._request(
                "GET", f"/{bucket}", query={"policyStatus": ""}, parse="text"
            )
        except APIError as exc:
            if exc.code == "NoSuchBucketPolicy":
                return False
            raise
        m = _IS_PUBLIC.search(text)
        if not m:
            raise APIError(200, "GET", f"/{bucket}?policyStatus", f"unreadable answer: {text[:200]}")
        return m.group(1).lower() == "true"

    # -- dedup ------------------------------------------------------------

    def get_bucket_dedup(self, bucket: str) -> dict:
        """The bucket's dedup policy at every level, and what it resolves
        to. Returned as the server sends it."""
        return self._request("GET", f"/_admin/buckets/{bucket}/dedup")

    def set_bucket_dedup(
        self, bucket: str, *, mode: str | None = None, scope: str | None = None
    ) -> dict:
        """Set the bucket's own dedup ``mode``/``scope``; a field left as
        ``None`` inherits from the tenant or cluster."""
        body: dict[str, Any] = {}
        if mode is not None:
            body["mode"] = mode
        if scope is not None:
            body["scope"] = scope
        return self._request("PUT", f"/_admin/buckets/{bucket}/dedup", body=body)

    def delete_bucket_dedup(self, bucket: str) -> dict:
        """Drop the bucket's own policy so it inherits everything."""
        return self._request("DELETE", f"/_admin/buckets/{bucket}/dedup")
