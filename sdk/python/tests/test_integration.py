"""The SDK against a real gateway.

Skipped unless pointed at one with a **system admin** credential:

    OBJECTIO_ENDPOINT=http://127.0.0.1:9000 \\
    OBJECTIO_ACCESS_KEY=... OBJECTIO_SECRET_KEY=... \\
    python -m pytest tests/test_integration.py -q

``objectio-aio --auth`` is enough: it writes the admin credential to
``<data>/meta/admin-creds.env``. Every test creates what it uses under a
unique name and removes it afterwards, so it can run against a shared
cluster. The tests that wait for a revocation take ~15 s each: that is the
gateways' credential cache, and the wait is the point.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from objectio import (
    APIError,
    Client,
    OIDCProvider,
    PublicAccessBlock,
    tenant_oidc_provider_name,
)

ENDPOINT = os.environ.get("OBJECTIO_ENDPOINT", "")
ACCESS_KEY = os.environ.get("OBJECTIO_ACCESS_KEY", "")
SECRET_KEY = os.environ.get("OBJECTIO_SECRET_KEY", "")

pytestmark = pytest.mark.skipif(
    not (ENDPOINT and ACCESS_KEY and SECRET_KEY),
    reason="OBJECTIO_ENDPOINT, OBJECTIO_ACCESS_KEY and OBJECTIO_SECRET_KEY not set",
)

# Longer than the gateways' 15 s credential cache.
REVOCATION_DEADLINE = 40.0

DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:obio:s3:::*/*"]}],
}


def uniq(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def s3(c: Client, method: str, path: str, *, query=None, body: bytes | None = None) -> str:
    """A bare S3 call, signed by the SDK's own plumbing. The SDK does no data
    operations; the tests need a few to prove what a credential can do."""
    return c._request(method, path, query=query, raw_body=body, parse="text")


def wait_until(predicate, deadline: float = REVOCATION_DEADLINE) -> float:
    start = time.monotonic()
    while True:
        if predicate():
            return time.monotonic() - start
        if time.monotonic() - start > deadline:
            raise AssertionError(f"condition not met within {deadline}s")
        time.sleep(1)


def refused(c: Client) -> bool:
    try:
        s3(c, "GET", "/")
        return False
    except APIError as exc:
        assert exc.status_code in (401, 403), exc
        return True


@pytest.fixture(scope="module")
def admin() -> Client:
    return Client(endpoint=ENDPOINT, access_key=ACCESS_KEY, secret_key=SECRET_KEY)


@pytest.fixture(scope="module")
def tenant(admin):
    """A tenant, a tenant admin in it and a client signed as that admin."""
    name = uniq("sdkt")
    admin.create_tenant(name, display_name="SDK test")
    user = admin.create_user("sdk-tenant-admin", tenant=name)
    admin.add_tenant_admin(name, user.user_id)
    key = admin.create_access_key(user.user_id)
    client = Client(endpoint=ENDPOINT, access_key=key.access_key_id, secret_key=key.secret_access_key)
    yield {"name": name, "user": user, "client": client}
    for u in admin.list_users():
        if u.tenant == name:
            for k in admin.list_access_keys(u.user_id):
                admin.delete_access_key(k.access_key_id)
            admin.delete_user(u.user_id)
    admin.delete_tenant(name)


# -- tenants ---------------------------------------------------------------


def test_tenant_and_tenant_admin(admin, tenant):
    name, user = tenant["name"], tenant["user"]
    t = admin.get_tenant(name)
    assert user.user_id in t.admin_users
    assert name in [x.name for x in admin.list_tenants()]

    # A partial update must not drop the tenant's admins (the server's PUT
    # replaces the whole tenant; the SDK merges).
    t = admin.update_tenant(name, display_name="renamed", quota_buckets=50)
    assert (t.display_name, t.quota_buckets) == ("renamed", 50)
    assert user.user_id in t.admin_users

    # The tenant admin sees its own tenant, and only its tenant's users.
    ta = tenant["client"]
    assert [x.name for x in ta.list_tenants()] == [name]
    assert {u.tenant for u in ta.list_users()} == {name}
    assert ta.get_user(user.user_id).tenant == name


# -- policies, groups, roles -----------------------------------------------


def test_policy_create_attach_detach(admin, tenant):
    name = tenant["name"]
    member = admin.create_user("sdk-policy-user", tenant=name)
    pol = uniq("pol")
    p = admin.create_policy(pol, DOC, tenant=name)
    try:
        assert (p.name, p.tenant, p.policy["Statement"][0]["Effect"]) == (pol, name, "Allow")
        assert admin.get_policy(pol, name).name == pol
        assert pol in [x.name for x in admin.list_policies(name)]
        # The tenant admin sees its tenant's policies without naming it.
        assert pol in [x.name for x in tenant["client"].list_policies()]

        doc2 = {**DOC, "Statement": [{**DOC["Statement"][0], "Action": ["s3:GetObject", "s3:ListBucket"]}]}
        assert admin.update_policy(pol, doc2, name).policy["Statement"][0]["Action"] == [
            "s3:GetObject",
            "s3:ListBucket",
        ]

        admin.attach_policy(pol, user_id=member.user_id)
        assert pol in admin.list_attached_policies(user_id=member.user_id)
        admin.detach_policy(pol, user_id=member.user_id)
        assert pol not in admin.list_attached_policies(user_id=member.user_id)
    finally:
        admin.delete_policy(pol, name)
        admin.delete_user(member.user_id)
    with pytest.raises(APIError) as exc:
        admin.get_policy(pol, name)
    assert exc.value.not_found


def test_tenant_admin_cannot_name_another_tenant(tenant):
    with pytest.raises(APIError) as exc:
        tenant["client"].list_policies("some-other-tenant")
    assert exc.value.forbidden


def test_group_and_member(admin, tenant):
    name = tenant["name"]
    member = admin.create_user("sdk-group-user", tenant=name)
    g = admin.create_group(uniq("grp"), tenant=name)
    pol = uniq("gpol")
    admin.create_policy(pol, DOC, tenant=name)
    try:
        assert g.tenant == name
        admin.add_group_member(g.group_id, member.user_id)
        assert member.user_id in admin.get_group(g.group_id).member_user_ids
        assert g.group_id in [x.group_id for x in admin.list_groups(name)]

        admin.attach_policy(pol, group_id=g.group_id)
        assert admin.list_attached_policies(group_id=g.group_id) == [pol]
        admin.detach_policy(pol, group_id=g.group_id)

        admin.remove_group_member(g.group_id, member.user_id)
        assert member.user_id not in admin.get_group(g.group_id).member_user_ids
    finally:
        admin.delete_group(g.group_id)
        admin.delete_policy(pol, name)
        admin.delete_user(member.user_id)
    with pytest.raises(APIError) as exc:
        admin.get_group(g.group_id)
    assert exc.value.not_found


def test_role_create_get_delete(admin, tenant):
    name = tenant["name"]
    role = uniq("role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "https://idp.example.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
            }
        ],
    }
    pol = uniq("rpol")
    admin.create_policy(pol, DOC, tenant=name)
    r = admin.create_role(role, trust, description="sdk", max_session_seconds=7200, tenant=name)
    try:
        assert r.arn.endswith(f":role/{role}") and name in r.arn
        assert (r.description, r.max_session_seconds) == ("sdk", 7200)

        admin.attach_policy(pol, role_name=role, tenant=name)
        got = admin.get_role(role, name)
        assert got.trust_policy["Statement"][0]["Action"] == "sts:AssumeRoleWithWebIdentity"
        assert any(p.endswith(pol) for p in got.attached_policies)

        assert admin.update_role(role, description="changed", tenant=name).description == "changed"
        assert role in [x.name for x in admin.list_roles(name)]
        admin.detach_policy(pol, role_name=role, tenant=name)
    finally:
        admin.delete_role(role, name)
        admin.delete_policy(pol, name)
    with pytest.raises(APIError) as exc:
        admin.get_role(role, name)
    assert exc.value.not_found


def test_sts_refuses_a_bogus_token_with_an_sts_code(tenant):
    # Unsigned client: STS needs no access key. A real token needs a real
    # identity provider; the refusal path is what can be checked here.
    sts = Client(endpoint=ENDPOINT)
    with pytest.raises(APIError) as exc:
        sts.assume_role_with_web_identity(
            f"arn:obio:iam::{tenant['name']}:role/nope", "not.a.jwt", "sdk-session"
        )
    assert exc.value.code in ("AccessDenied", "InvalidIdentityToken")


# -- suspension and deactivation --------------------------------------------


def test_suspend_and_activate_user(admin, tenant):
    user = admin.create_user("sdk-suspend", tenant=tenant["name"])
    key = admin.create_access_key(user.user_id)
    c = Client(endpoint=ENDPOINT, access_key=key.access_key_id, secret_key=key.secret_access_key)
    try:
        assert not refused(c)
        assert admin.suspend_user(user.user_id).status == "suspended"
        assert admin.get_user(user.user_id).status == "suspended"
        assert [u.status for u in admin.list_users() if u.user_id == user.user_id] == ["suspended"]
        wait_until(lambda: refused(c))
        assert admin.activate_user(user.user_id).status == "active"
        wait_until(lambda: not refused(c))
    finally:
        admin.delete_access_key(key.access_key_id)
        admin.delete_user(user.user_id)


def test_deactivate_access_key(admin, tenant):
    user = admin.create_user("sdk-deactivate", tenant=tenant["name"])
    key = admin.create_access_key(user.user_id)
    c = Client(endpoint=ENDPOINT, access_key=key.access_key_id, secret_key=key.secret_access_key)
    try:
        assert not refused(c)
        assert admin.deactivate_access_key(key.access_key_id).status == "inactive"
        (listed,) = admin.list_access_keys(user.user_id)
        assert listed.status == "inactive"
        wait_until(lambda: refused(c))
        admin.activate_access_key(key.access_key_id)
        wait_until(lambda: not refused(c))
    finally:
        admin.delete_access_key(key.access_key_id)
        admin.delete_user(user.user_id)


def test_cannot_deactivate_own_key(admin):
    with pytest.raises(APIError) as exc:
        admin.deactivate_access_key(admin.access_key)
    assert exc.value.status_code == 400


# -- public access block -------------------------------------------------


def public_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:obio:s3:::{bucket}/*",
            }
        ],
    }


def put_policy_via_s3(c: Client, bucket: str, policy: dict) -> None:
    import json

    s3(c, "PUT", f"/{bucket}", query={"policy": ""}, body=json.dumps(policy).encode())


def test_public_access_block_levels(admin, tenant):
    name = tenant["name"]
    cluster = admin.get_public_access_block()
    assert cluster.tenant == "" and cluster.new_buckets_blocked is not None

    # Tenant level.
    out = admin.put_public_access_block(PublicAccessBlock(block_public_policy=True), tenant=name)
    assert out.block_public_policy and out.tenant == name
    got = admin.get_public_access_block(name)
    assert (got.block_public_policy, got.restrict_public_buckets, got.tenant) == (True, False, name)
    admin.delete_public_access_block(name)
    assert admin.get_public_access_block(name) == PublicAccessBlock(tenant=name)

    # Bucket level: a new bucket starts fully blocked (unless the cluster
    # turned that off), and a public policy is refused until it is lifted.
    bucket = uniq("sdk-pab-")
    admin.create_bucket(bucket)
    try:
        if cluster.new_buckets_blocked:
            assert admin.get_bucket_public_access_block(bucket) == PublicAccessBlock.all_blocked()
        assert admin.get_bucket_policy_status(bucket) is False  # no policy at all

        admin.put_bucket_public_access_block(bucket, PublicAccessBlock(block_public_policy=True))
        with pytest.raises(APIError) as exc:
            put_policy_via_s3(admin, bucket, public_policy(bucket))
        assert exc.value.code == "AccessDenied"

        admin.put_bucket_public_access_block(bucket, PublicAccessBlock())
        assert admin.get_bucket_public_access_block(bucket) == PublicAccessBlock()
        put_policy_via_s3(admin, bucket, public_policy(bucket))
        assert admin.get_bucket_policy_status(bucket) is True

        admin.delete_bucket_policy(bucket)
        assert admin.get_bucket_policy_status(bucket) is False
        admin.delete_bucket_public_access_block(bucket)
        assert admin.get_bucket_public_access_block(bucket) is None
    finally:
        admin.delete_bucket_policy(bucket)
        admin.delete_bucket(bucket)


def test_admin_bucket_policy_route_honours_block_public_policy(admin):
    bucket = uniq("sdk-pab-admin-")
    admin.create_bucket(bucket)
    try:
        admin.put_bucket_public_access_block(bucket, PublicAccessBlock.all_blocked())
        with pytest.raises(APIError):
            admin.put_bucket_policy(bucket, public_policy(bucket))
    finally:
        admin.delete_bucket_policy(bucket)
        admin.delete_bucket(bucket)


def test_cluster_new_buckets_blocked_toggle(admin):
    before = admin.get_public_access_block()
    bucket = uniq("sdk-nbb-")
    try:
        out = admin.put_public_access_block(PublicAccessBlock(), new_buckets_blocked=False)
        assert out.new_buckets_blocked is False
        assert admin.get_public_access_block().new_buckets_blocked is False
        admin.create_bucket(bucket)
        assert admin.get_bucket_public_access_block(bucket) is None
    finally:
        admin.delete_bucket(bucket)
        # Put back what was there (an absent document reads as all-false
        # flags with new buckets blocked).
        if before == PublicAccessBlock(new_buckets_blocked=True):
            admin.delete_public_access_block()
        else:
            flags = PublicAccessBlock(
                before.block_public_acls,
                before.ignore_public_acls,
                before.block_public_policy,
                before.restrict_public_buckets,
            )
            admin.put_public_access_block(flags, new_buckets_blocked=before.new_buckets_blocked)
    assert admin.get_public_access_block() == before


# -- bucket provisioning ---------------------------------------------------


def test_provision_rotate_deprovision(admin, tenant):
    ta, ta_user = tenant["client"], tenant["user"]
    bucket = uniq("sdk-prov-")
    access = ta.provision_bucket(bucket, ta_user.user_id)
    try:
        assert access.scope == f"s3://{bucket}/"
        scoped = Client(endpoint=ENDPOINT, access_key=access.access_key_id, secret_key=access.secret_key)
        s3(scoped, "PUT", f"/{bucket}/hello.txt", body=b"hi")
        assert s3(scoped, "GET", f"/{bucket}/hello.txt") == "hi"
        # A scoped key is refused on the management API by design.
        with pytest.raises(APIError) as exc:
            scoped.list_users()
        assert exc.value.forbidden

        rotated = ta.rotate_bucket_key(ta_user.user_id, bucket, read_only=True)
        assert rotated.access_key_id != access.access_key_id and rotated.read_only
        ro = Client(endpoint=ENDPOINT, access_key=rotated.access_key_id, secret_key=rotated.secret_key)
        assert s3(ro, "GET", f"/{bucket}/hello.txt") == "hi"
        with pytest.raises(APIError):
            s3(ro, "PUT", f"/{bucket}/nope.txt", body=b"x")

        s3(scoped, "DELETE", f"/{bucket}/hello.txt")
    finally:
        ta.deprovision_bucket(ta_user.user_id, bucket)
    assert bucket not in [b.name for b in admin.list_buckets()]
    assert not [
        k for k in admin.list_access_keys(ta_user.user_id) if k.scope.startswith(f"s3://{bucket}/")
    ]


# -- config and identity providers ----------------------------------------


def test_config_get_set(admin):
    key = f"sdk-test/{uniq('k')}"
    try:
        e = admin.set_config(key, {"a": 1, "b": [True]})
        assert e.key == key and e.version >= 1
        got = admin.get_config(key)
        assert got.value == {"a": 1, "b": [True]}
        assert key in [x.key for x in admin.list_config("sdk-test/")]
        admin.set_config(key, "plain")
        assert admin.get_config(key).value == "plain"
    finally:
        admin.delete_config(key)
    with pytest.raises(APIError) as exc:
        admin.get_config(key)
    assert exc.value.not_found


def test_tenant_oidc_provider(admin, tenant):
    name = tenant_oidc_provider_name(tenant["name"])
    cfg = OIDCProvider(
        issuer_url="https://idp.example.com/realms/x",
        client_id="objectio",
        client_secret="s3cret",
        scopes="openid email",
    )
    try:
        # The tenant admin may manage its own tenant's provider.
        tenant["client"].put_oidc_provider(name, cfg)
        got = admin.get_oidc_provider(name)
        assert (got.issuer_url, got.scopes, got.client_secret) == (
            cfg.issuer_url,
            "openid email",
            "********",
        )
        assert name in [p.name for p in admin.list_oidc_providers()]
        # Writing it back unchanged would store the asterisks; refused.
        with pytest.raises(ValueError):
            admin.put_oidc_provider(name, got)
    finally:
        admin.delete_oidc_provider(name)


# -- cluster ---------------------------------------------------------------


def test_cluster_info_nodes_pools(admin):
    info = admin.cluster_info()
    assert isinstance(info, dict) and info.get("osds")
    nodes = admin.list_nodes()
    assert nodes
    assert isinstance(admin.list_pools(), list)
    assert "tree" in admin.topology()
    assert "drains" in admin.drain_status()
    assert "paused" in admin.rebalance_status()
    status = admin.kms_status()
    assert status["backend"] in ("local", "external", "disabled")


def test_warehouse_create_list_delete(admin):
    name = uniq("sdkwh")
    w = admin.create_warehouse(name)
    try:
        assert w.bucket == f"iceberg-{name}"
        assert name in [x.name for x in admin.list_warehouses()]
    finally:
        admin.delete_warehouse(name)
    assert name not in [x.name for x in admin.list_warehouses()]
