"""Request shapes, against a local stub server.

Each test checks what goes on the wire — method, path, query, body — for a
method, and how the answer is read back. The shapes are taken from the
gateway's handlers (bin/objectio-gateway/src/{admin,iam_admin,public_access,
sts_api,kms,prom}.rs); tests/test_integration.py runs the same calls against
a real gateway.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from objectio import (
    APIError,
    BucketAccess,
    Client,
    ObjectIOError,
    OIDCProvider,
    PublicAccessBlock,
    tenant_oidc_provider_name,
)


class Stub:
    """Records every request; answers from a FIFO of canned responses
    (default: 200 with ``{}``)."""

    def __init__(self):
        self.requests = []
        self.responses = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                parsed = urllib.parse.urlsplit(self.path)
                stub.requests.append(
                    {
                        "method": self.command,
                        "path": urllib.parse.unquote(parsed.path),
                        "query": dict(
                            urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                        ),
                        "body": body,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    }
                )
                status, ctype, out = (
                    stub.responses.pop(0) if stub.responses else (200, "application/json", b"{}")
                )
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_PUT = do_POST = do_DELETE = _handle

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}"

    def json(self, payload, status=200):
        self.responses.append((status, "application/json", json.dumps(payload).encode()))

    def xml(self, text, status=200):
        self.responses.append((status, "application/xml", text.encode()))

    def empty(self, status=204):
        self.responses.append((status, "text/plain", b""))

    @property
    def last(self):
        return self.requests[-1]

    def body(self, i=-1):
        return json.loads(self.requests[i]["body"])


@pytest.fixture(scope="module")
def _server():
    # One server for the module: shutting one down waits out its poll
    # interval, which per test adds up.
    s = Stub()
    yield s
    s.server.shutdown()
    s.server.server_close()


@pytest.fixture
def stub(_server):
    _server.requests.clear()
    _server.responses.clear()
    return _server


@pytest.fixture
def client(stub):
    return Client(endpoint=stub.endpoint, access_key="AKIATEST", secret_key="secret")


# -- construction ----------------------------------------------------------


def test_endpoint_only_client_refuses_signed_calls(stub):
    c = Client(endpoint=stub.endpoint)
    assert not c.has_credentials
    with pytest.raises(ObjectIOError, match="needs credentials"):
        c.list_users()
    assert stub.requests == []


def test_half_a_credential_is_a_configuration_error():
    with pytest.raises(ValueError):
        Client(endpoint="http://x", access_key="AKIA")


def test_signed_calls_carry_sigv4(client, stub):
    client.list_users()
    assert stub.last["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIATEST/")


# -- users and keys ------------------------------------------------------


def test_get_user(client, stub):
    stub.json({"user_id": "u1", "display_name": "a", "status": "active", "tenant": "t", "new": 1})
    u = client.get_user("u1")
    assert (stub.last["method"], stub.last["path"]) == ("GET", "/_admin/users/u1")
    assert (u.user_id, u.status, u.tenant) == ("u1", "active", "t")


def test_update_user_sends_only_what_changes(client, stub):
    stub.json({"user_id": "u1", "email": "a@b"})
    client.update_user("u1", email="a@b")
    assert (stub.last["method"], stub.last["path"]) == ("PUT", "/_admin/users/u1")
    assert stub.body() == {"email": "a@b"}


def test_suspend_and_activate_user(client, stub):
    stub.json({"user_id": "u1", "status": "suspended"})
    assert client.suspend_user("u1").status == "suspended"
    assert stub.body() == {"status": "suspended"}
    stub.json({"user_id": "u1", "status": "active"})
    client.activate_user("u1")
    assert stub.body() == {"status": "active"}


def test_deactivate_and_activate_access_key(client, stub):
    stub.json({"access_key_id": "AK1", "user_id": "u1", "status": "inactive"})
    k = client.deactivate_access_key("AK1")
    assert (stub.last["method"], stub.last["path"]) == ("PUT", "/_admin/access-keys/AK1")
    assert stub.body() == {"status": "inactive"}
    assert (k.access_key_id, k.status) == ("AK1", "inactive")
    stub.json({"access_key_id": "AK1", "status": "active"})
    client.activate_access_key("AK1")
    assert stub.body() == {"status": "active"}


# -- tenants ---------------------------------------------------------------


def test_tenants_are_typed(client, stub):
    stub.json([{"name": "t1", "admin_users": ["u1"], "quota_bytes": 5, "dedup": None}])
    (t,) = client.list_tenants()
    assert (t.name, t.admin_users, t.quota_bytes) == ("t1", ["u1"], 5)


def test_update_tenant_keeps_what_it_does_not_change(client, stub):
    # The server's PUT replaces the whole tenant; without the read first,
    # changing the quota would drop the tenant's admins.
    stub.json({"name": "t1", "admin_users": ["u1"], "quota_bytes": 1, "enabled": True})
    stub.json({"name": "t1", "admin_users": ["u1"], "quota_bytes": 9})
    t = client.update_tenant("t1", quota_bytes=9)
    get, put = stub.requests
    assert (get["method"], get["path"]) == ("GET", "/_admin/tenants/t1")
    assert (put["method"], put["path"]) == ("PUT", "/_admin/tenants/t1")
    assert json.loads(put["body"]) == {
        "name": "t1",
        "admin_users": ["u1"],
        "quota_bytes": 9,
        "enabled": True,
    }
    assert t.quota_bytes == 9


# -- policies --------------------------------------------------------------

DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}


def test_list_policies_names_the_tenant_only_when_given(client, stub):
    stub.json({"policies": [{"name": "p", "tenant": "t", "policy": DOC, "shared": False}]})
    (p,) = client.list_policies("t")
    assert stub.last["query"] == {"tenant": "t"}
    assert (p.name, p.policy) == ("p", DOC)
    client.list_policies()
    assert stub.last["query"] == {}


def test_create_policy(client, stub):
    stub.json({"name": "p", "tenant": "t"}, status=201)
    client.create_policy("p", DOC, tenant="t")
    assert (stub.last["method"], stub.last["path"]) == ("POST", "/_admin/policies")
    assert stub.body() == {"name": "p", "policy": DOC, "tenant": "t"}
    stub.json({"name": "s", "shared": True}, status=201)
    client.create_policy("s", DOC, shared=True)
    assert stub.body() == {"name": "s", "policy": DOC, "shared": True}


def test_get_update_delete_policy(client, stub):
    stub.json({"name": "p"})
    stub.json({"name": "p"})
    client.get_policy("p", "t")
    assert (stub.last["method"], stub.last["path"], stub.last["query"]) == (
        "GET",
        "/_admin/policies/p",
        {"tenant": "t"},
    )
    client.update_policy("p", DOC, "t")
    assert (stub.last["method"], stub.last["query"]) == ("PUT", {"tenant": "t"})
    assert stub.body() == {"policy": DOC}
    stub.empty()
    client.delete_policy("p", "t")
    assert (stub.last["method"], stub.last["path"]) == ("DELETE", "/_admin/policies/p")


def test_attach_needs_exactly_one_target(client, stub):
    with pytest.raises(ValueError):
        client.attach_policy("p")
    with pytest.raises(ValueError):
        client.attach_policy("p", user_id="u", group_id="g")
    assert stub.requests == []


def test_attach_detach_and_list_attached(client, stub):
    client.attach_policy("p", role_name="r", tenant="t")
    assert (stub.last["method"], stub.last["path"]) == ("POST", "/_admin/policies/attach")
    assert stub.body() == {"policy_name": "p", "role_name": "r", "tenant": "t"}
    client.detach_policy("p", user_id="u1")
    assert stub.last["path"] == "/_admin/policies/detach"
    assert stub.body() == {"policy_name": "p", "user_id": "u1"}
    stub.json({"policy_names": ["p", "q"]})
    assert client.list_attached_policies(group_id="g1") == ["p", "q"]
    assert (stub.last["method"], stub.last["path"], stub.last["query"]) == (
        "GET",
        "/_admin/policies/attached",
        {"group_id": "g1"},
    )


# -- groups ----------------------------------------------------------------


def test_groups(client, stub):
    stub.json({"group_id": "g1", "group_name": "devs", "tenant": "t", "member_user_ids": []})
    g = client.create_group("devs", tenant="t")
    assert stub.body() == {"group_name": "devs", "tenant": "t"}
    assert g.group_id == "g1"
    client.add_group_member("g1", "u1")
    assert (stub.last["method"], stub.last["path"]) == ("POST", "/_admin/groups/g1/members")
    assert stub.body() == {"user_id": "u1"}
    client.remove_group_member("g1", "u1")
    assert (stub.last["method"], stub.last["path"]) == ("DELETE", "/_admin/groups/g1/members/u1")
    stub.json({"groups": [{"group_id": "g1"}]})
    assert [g.group_id for g in client.list_groups("t")] == ["g1"]
    assert stub.last["query"] == {"tenant": "t"}


# -- roles -----------------------------------------------------------------

TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": "x"}, "Action": "sts:AssumeRoleWithWebIdentity"}]}


def test_create_and_update_role(client, stub):
    stub.json({"name": "r", "arn": "arn:obio:iam::t:role/r", "trust_policy": TRUST})
    r = client.create_role("r", TRUST, description="d", max_session_seconds=7200, tenant="t")
    assert (stub.last["method"], stub.last["path"]) == ("POST", "/_admin/roles")
    assert stub.body() == {
        "name": "r",
        "trust_policy": TRUST,
        "description": "d",
        "max_session_seconds": 7200,
        "tenant": "t",
    }
    assert r.arn == "arn:obio:iam::t:role/r"
    stub.json({"name": "r", "description": "new"})
    client.update_role("r", description="new", tenant="t")
    assert (stub.last["method"], stub.last["path"], stub.last["query"]) == (
        "PUT",
        "/_admin/roles/r",
        {"tenant": "t"},
    )
    assert stub.body() == {"description": "new"}


def test_get_role_carries_attached_policies(client, stub):
    stub.json({"name": "r", "attached_policies": ["t/p"]})
    assert client.get_role("r", "t").attached_policies == ["t/p"]


# -- STS -------------------------------------------------------------------

STS_OK = """<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA1</AccessKeyId>
<SecretAccessKey>sek</SecretAccessKey><SessionToken>tok</SessionToken>
<Expiration>2026-10-02T13:00:00Z</Expiration></Credentials>
<AssumedRoleUser><Arn>arn:obio:sts::t:assumed-role/r/s1</Arn><AssumedRoleId>x:s1</AssumedRoleId></AssumedRoleUser>
</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"""

STS_DENIED = """<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type>
<Code>AccessDenied</Code><Message>Not authorized</Message></Error></ErrorResponse>"""


def test_assume_role_is_unsigned_and_parses_credentials(stub):
    c = Client(endpoint=stub.endpoint)  # no keys: the token is the proof
    stub.xml(STS_OK)
    creds = c.assume_role_with_web_identity(
        "arn:obio:iam::t:role/r", "jwt.token.here", "s1", duration_seconds=900
    )
    req = stub.last
    assert (req["method"], req["path"]) == ("POST", "/")
    assert "authorization" not in req["headers"]
    assert req["headers"]["content-type"] == "application/x-www-form-urlencoded"
    assert dict(urllib.parse.parse_qsl(req["body"].decode())) == {
        "Action": "AssumeRoleWithWebIdentity",
        "Version": "2011-06-15",
        "RoleArn": "arn:obio:iam::t:role/r",
        "WebIdentityToken": "jwt.token.here",
        "RoleSessionName": "s1",
        "DurationSeconds": "900",
    }
    assert (creds.access_key_id, creds.secret_access_key, creds.session_token) == (
        "ASIA1",
        "sek",
        "tok",
    )
    assert creds.expiration == datetime(2026, 10, 2, 13, 0, tzinfo=timezone.utc)
    assert creds.assumed_role_arn == "arn:obio:sts::t:assumed-role/r/s1"
    assert creds.boto3_kwargs("http://e")["aws_session_token"] == "tok"


def test_assume_role_stays_unsigned_on_a_signed_client(client, stub):
    # A signed POST / is S3, not STS — the gateway routes on the signature.
    stub.xml(STS_OK)
    client.assume_role_with_web_identity("arn:obio:iam::t:role/r", "t", "s1")
    assert "authorization" not in stub.last["headers"]
    assert "DurationSeconds" not in stub.last["body"].decode()


def test_sts_errors_carry_the_sts_code(stub):
    stub.responses.append((403, "text/xml", STS_DENIED.encode()))
    with pytest.raises(APIError) as exc:
        Client(endpoint=stub.endpoint).assume_role_with_web_identity("arn:obio:iam::t:role/r", "t", "s1")
    assert exc.value.status_code == 403
    assert exc.value.code == "AccessDenied"
    assert exc.value.forbidden


# -- public access block ---------------------------------------------------


def test_cluster_block_round_trip(client, stub):
    stub.json(
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
            "tenant": "",
            "new_buckets_blocked": True,
        }
    )
    b = client.get_public_access_block()
    assert (stub.last["path"], stub.last["query"]) == ("/_admin/public-access-block", {})
    assert b.block_public_policy and not b.restrict_public_buckets
    assert b.new_buckets_blocked is True

    stub.json({"BlockPublicPolicy": True, "new_buckets_blocked": False})
    client.put_public_access_block(
        PublicAccessBlock(block_public_policy=True), new_buckets_blocked=False
    )
    assert stub.last["method"] == "PUT"
    assert stub.body() == {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": False,
        "new_buckets_blocked": False,
    }


def test_tenant_block(client, stub):
    stub.json({"RestrictPublicBuckets": True})
    out = client.put_public_access_block(
        PublicAccessBlock(restrict_public_buckets=True), tenant="t"
    )
    assert stub.last["query"] == {"tenant": "t"}
    assert out.tenant == "t" and out.restrict_public_buckets
    stub.empty()
    client.delete_public_access_block("t")
    assert (stub.last["method"], stub.last["query"]) == ("DELETE", {"tenant": "t"})
    with pytest.raises(ValueError):
        client.put_public_access_block(PublicAccessBlock(), tenant="t", new_buckets_blocked=True)


BUCKET_PAB = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<PublicAccessBlockConfiguration '
    'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls>'
    "<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>false</BlockPublicPolicy>"
    "<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
)


def test_bucket_block_is_s3_xml(client, stub):
    stub.xml(BUCKET_PAB)
    b = client.get_bucket_public_access_block("b1")
    assert (stub.last["method"], stub.last["path"], stub.last["query"]) == (
        "GET",
        "/b1",
        {"publicAccessBlock": ""},
    )
    assert b == PublicAccessBlock(True, True, False, True)

    stub.empty(200)
    client.put_bucket_public_access_block("b1", PublicAccessBlock.all_blocked())
    assert stub.last["method"] == "PUT"
    assert stub.last["headers"]["content-type"] == "application/xml"
    assert PublicAccessBlock.from_xml(stub.last["body"].decode()) == PublicAccessBlock.all_blocked()

    stub.empty()
    client.delete_bucket_public_access_block("b1")
    assert (stub.last["method"], stub.last["query"]) == ("DELETE", {"publicAccessBlock": ""})


def test_bucket_without_a_block_reads_none(client, stub):
    stub.responses.append(
        (
            404,
            "application/xml",
            b"<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>",
        )
    )
    assert client.get_bucket_public_access_block("b1") is None


def test_policy_status(client, stub):
    stub.xml("<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>")
    assert client.get_bucket_policy_status("b1") is True
    assert stub.last["query"] == {"policyStatus": ""}
    stub.responses.append(
        (404, "application/xml", b"<Error><Code>NoSuchBucketPolicy</Code></Error>")
    )
    assert client.get_bucket_policy_status("b1") is False
    stub.responses.append(
        (404, "application/xml", b"<Error><Code>NoSuchBucket</Code></Error>")
    )
    with pytest.raises(APIError) as exc:
        client.get_bucket_policy_status("b1")
    assert exc.value.code == "NoSuchBucket"


# -- config and OIDC -------------------------------------------------------


def test_config(client, stub):
    stub.json([{"key": "a/b", "value": {"x": 1}, "version": 2}])
    (e,) = client.list_config("a/")
    assert (stub.last["path"], stub.last["query"]) == ("/_admin/config", {"prefix": "a/"})
    assert (e.key, e.value, e.version) == ("a/b", {"x": 1}, 2)
    stub.json({"key": "a/b", "value": [1, 2], "version": 3})
    client.set_config("a/b", [1, 2])
    assert (stub.last["method"], stub.last["path"]) == ("PUT", "/_admin/config/a/b")
    assert stub.body() == [1, 2]
    stub.empty()
    client.delete_config("a/b")
    assert (stub.last["method"], stub.last["path"]) == ("DELETE", "/_admin/config/a/b")


def test_oidc_providers(client, stub):
    stub.json(
        [
            {
                "key": "identity/openid/t-acme",
                "value": {"issuer_url": "https://i", "client_id": "c", "client_secret": "********", "custom": 1},
            }
        ]
    )
    (p,) = client.list_oidc_providers()
    assert stub.last["query"] == {"prefix": "identity/openid/"}
    assert (p.name, p.issuer_url, p.extra) == ("t-acme", "https://i", {"custom": 1})

    # Writing back a read would store the asterisks as the secret.
    with pytest.raises(ValueError):
        client.put_oidc_provider("t-acme", p)

    stub.json({"key": "identity/openid/t-acme", "value": {"issuer_url": "https://i", "client_id": "c"}})
    client.put_oidc_provider(
        tenant_oidc_provider_name("ACME"),
        OIDCProvider(issuer_url="https://i", client_id="c", client_secret="s", system_admin=False),
    )
    assert (stub.last["method"], stub.last["path"]) == ("PUT", "/_admin/config/identity/openid/t-acme")
    assert stub.body() == {
        "issuer_url": "https://i",
        "client_id": "c",
        "client_secret": "s",
        "system_admin": False,
    }


# -- cluster ---------------------------------------------------------------


def test_cluster_calls(client, stub):
    for call, method, path in [
        (client.cluster_info, "GET", "/_admin/cluster-info"),
        (client.list_nodes, "GET", "/_admin/nodes"),
        (client.topology, "GET", "/_admin/topology"),
        (client.usage, "GET", "/_admin/usage"),
        (client.drain_status, "GET", "/_admin/drain-status"),
        (client.rebalance_status, "GET", "/_admin/rebalance-status"),
        (client.pause_rebalance, "POST", "/_admin/rebalance/pause"),
        (client.resume_rebalance, "POST", "/_admin/rebalance/resume"),
        (client.list_pools, "GET", "/_admin/pools"),
        (client.kms_status, "GET", "/_admin/kms/status"),
    ]:
        call()
        assert (stub.last["method"], stub.last["path"]) == (method, path)

    client.set_osd_admin_state("ab" * 16, "out")
    assert (stub.last["method"], stub.last["path"]) == ("PUT", f"/_admin/osds/{'ab' * 16}/admin-state")
    assert stub.body() == {"state": "out"}

    client.list_placement_groups("p1", start_after=5, max_results=10)
    assert (stub.last["path"], stub.last["query"]) == (
        "/_admin/pools/p1/placement-groups",
        {"start_after": "5", "max": "10"},
    )


def test_update_pool_keeps_what_it_does_not_change(client, stub):
    stub.json({"name": "p1", "ec_k": 4, "ec_m": 2, "enabled": True})
    stub.json({"name": "p1", "ec_k": 4, "ec_m": 2, "enabled": False})
    client.update_pool("p1", enabled=False)
    assert stub.body() == {"name": "p1", "ec_k": 4, "ec_m": 2, "enabled": False}


def test_kms_keys_follow_pagination(client, stub):
    stub.json({"keys": [{"key_id": "k1"}], "next_page_token": "n"})
    stub.json({"keys": [{"key_id": "k2"}], "next_page_token": ""})
    assert [k.key_id for k in client.list_kms_keys()] == ["k1", "k2"]
    assert stub.requests[1]["query"] == {"max_results": "100", "page_token": "n"}
    stub.json({"key_id": "k3", "status": "Enabled"}, status=201)
    assert client.create_kms_key("k3", "d").status == "Enabled"
    assert stub.body() == {"key_id": "k3", "description": "d"}


def test_kms_xml_errors_carry_their_code(client, stub):
    stub.responses.append(
        (503, "application/xml", b"<Error><Code>ServiceUnavailable</Code><Message>m</Message></Error>")
    )
    with pytest.raises(APIError) as exc:
        client.list_kms_keys()
    assert exc.value.code == "ServiceUnavailable"


def test_warehouses(client, stub):
    stub.json({"name": "w", "bucket": "iceberg-w"})
    w = client.create_warehouse("w", tenant="t", properties={"a": "b"})
    assert stub.body() == {"name": "w", "tenant": "t", "properties": {"a": "b"}}
    assert w.bucket == "iceberg-w"
    stub.empty()
    client.delete_warehouse("w")
    assert (stub.last["method"], stub.last["path"]) == ("DELETE", "/_admin/warehouses/w")


def test_metrics(client, stub):
    stub.json({"status": "success", "data": {}})
    assert client.metrics_query("up", time=1700000000)["status"] == "success"
    assert stub.last["query"] == {"query": "up", "time": "1700000000"}
    client.metrics_query_range("up", 1, 61, 15)
    assert (stub.last["path"], stub.last["query"]) == (
        "/_admin/metrics/query_range",
        {"query": "up", "start": "1", "end": "61", "step": "15"},
    )


# -- bucket provisioning ---------------------------------------------------


def test_provision_bucket(client, stub):
    stub.json({})
    stub.json({"access_key_id": "AK", "secret_access_key": "SK", "scope": "s3://b1/"})
    access = client.provision_bucket("b1", "u1", tenant="t", read_only=True)
    create, mint = stub.requests
    assert (create["path"], json.loads(create["body"])) == (
        "/_admin/buckets",
        {"name": "b1", "tenant": "t"},
    )
    assert (mint["path"], json.loads(mint["body"])) == (
        "/_admin/users/u1/access-keys",
        {"operation": "R", "scope": "s3://b1/"},
    )
    assert access == BucketAccess(
        bucket="b1", access_key_id="AK", secret_key="SK", scope="s3://b1/", tenant="t", read_only=True
    )
    assert access.boto3_kwargs("http://e")["aws_secret_access_key"] == "SK"


def test_deprovision_bucket_revokes_only_its_keys(client, stub):
    stub.json(
        {
            "access_keys": [
                {"access_key_id": "A", "scope": "s3://b1/"},
                {"access_key_id": "B", "scope": "s3://b10/"},
                {"access_key_id": "C", "scope": ""},
            ]
        }
    )
    client.deprovision_bucket("u1", "b1")
    calls = [(r["method"], r["path"]) for r in stub.requests]
    assert calls == [
        ("GET", "/_admin/users/u1/access-keys"),
        ("DELETE", "/_admin/access-keys/A"),
        ("DELETE", "/_admin/buckets/b1"),
    ]


def test_list_status_numbers_are_normalised(client, stub):
    # The list endpoints send the enum number; get/update spell it out.
    stub.json({"users": [{"user_id": "u1", "status": "1"}, {"user_id": "u2", "status": "0"}]})
    assert [u.status for u in client.list_users()] == ["suspended", "active"]
    stub.json({"access_keys": [{"access_key_id": "A", "status": "1"}]})
    assert client.list_access_keys("u1")[0].status == "inactive"
