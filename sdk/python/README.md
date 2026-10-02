# objectio-sdk

Python client for the **ObjectIO management API** — the `/_admin/*` surface
for tenants, users, access keys, buckets and bucket policies, IAM policies,
groups and roles, identity providers, Block Public Access, pools, KMS and
cluster status — plus STS `AssumeRoleWithWebIdentity`.

```bash
pip install objectio-sdk
```
```python
from objectio import Client
```

> The distribution is `objectio-sdk` because `objectio` is taken on PyPI by an
> unrelated package. The import is still `objectio`.

It deliberately does **not** do S3 data operations. Use boto3 (or
mountpoint-s3, s3fs, rclone) for those, pointed at the same endpoint with a
credential this mints.

**No dependencies.** SigV4 is implemented on the standard library, so this
installs into an operator or a provisioning job without dragging in botocore.

## Configure

```python
app = Client.from_env()
```

| | |
|---|---|
| `OBJECTIO_ENDPOINT` or `OBJECTIO_URL` | gateway base URL — **required** |
| `OBJECTIO_ACCESS_KEY` · `OBJECTIO_ACCESS_KEY_FILE` · `AWS_ACCESS_KEY_ID` | |
| `OBJECTIO_SECRET_KEY` · `OBJECTIO_SECRET_KEY_FILE` · `AWS_SECRET_ACCESS_KEY` | |
| `OBJECTIO_REGION` · `AWS_REGION` · `AWS_DEFAULT_REGION` | default `us-east-1` |
| `OBJECTIO_PROVISIONER_USER_ID` | the user bucket-scoped keys are minted on |

Prefer the `_FILE` forms in Kubernetes — that is how a Secret is projected, and
a secret in the environment is readable from `/proc` and lands in crash dumps.
File contents are trimmed: a projected Secret ends in a newline, and a `\n`
inside a signing key produces a `SignatureDoesNotMatch` that reads like a wrong
password.

The credential must be **unscoped**. A key confined to a bucket is refused on
the management API — which is what stops a credential handed to a workload from
minting itself a wider one.

## Provision a bucket

One bucket, and one credential confined to it:

```python
access = app.provision_bucket("bucket-1", provisioner_user_id=provisioner_user_id)

import boto3
s3 = boto3.client("s3", **access.boto3_kwargs("https://s3.example.com"))
s3.put_object(Bucket=access.bucket, Key="hello.txt", Body=b"hi")
```

Two calls, no bucket policy and no extra user: the provisioner owns the bucket
it just created — with no policy attached ObjectIO authorizes on ownership —
and the scope narrows that to the one bucket.

`rotate_bucket_key` mints a replacement while the old key still works;
`deprovision_bucket` revokes the keys and drops the bucket, but will not
delete objects — losing a bucket's data should take more than one call.

## What else it covers

| Area | Methods |
|---|---|
| Users, keys | `get_user` `update_user` `suspend_user` `activate_user` · `update_access_key` `deactivate_access_key` `activate_access_key` |
| Tenants | `create_tenant` `get_tenant` `list_tenants` `update_tenant` `delete_tenant` `add_tenant_admin` `remove_tenant_admin` |
| IAM policies | `list_policies` `create_policy` `get_policy` `update_policy` `delete_policy` · `attach_policy` `detach_policy` `list_attached_policies` |
| Groups | `list_groups` `create_group` `get_group` `delete_group` `add_group_member` `remove_group_member` |
| Roles, STS | `list_roles` `create_role` `get_role` `update_role` `delete_role` · `assume_role_with_web_identity` |
| Identity providers | `list_oidc_providers` `get_oidc_provider` `put_oidc_provider` `delete_oidc_provider` · `tenant_oidc_provider_name()` |
| Config | `list_config` `get_config` `set_config` `delete_config` |
| Block Public Access | `get/put/delete_public_access_block` (cluster or tenant) · `get/put/delete_bucket_public_access_block` · `get_bucket_policy_status` |
| Dedup | `get_bucket_dedup` `set_bucket_dedup` `delete_bucket_dedup` |
| Cluster | `cluster_info` `list_nodes` `topology` `usage` `drain_status` `rebalance_status` `pause_rebalance` `resume_rebalance` `set_osd_admin_state` |
| Pools | `list_pools` `create_pool` `get_pool` `update_pool` `delete_pool` `list_placement_groups` |
| KMS | `kms_status` `list_kms_keys` `create_kms_key` `get_kms_key` `delete_kms_key` |
| Iceberg | `list_warehouses` `create_warehouse` `delete_warehouse` |
| Metrics | `metrics_query` `metrics_query_range` (needs the gateway's `--prometheus-url`) |

IAM objects come back as dataclasses (`User`, `AccessKey`, `Tenant`, `Policy`,
`Group`, `Role`, `PublicAccessBlock`, `Credentials` …). The large operational
shapes — cluster info, nodes, topology, usage, pools, metrics — are returned
as the server's JSON (`dict`), since they are read by people and dashboards
and change faster than a client release.

Methods that act in a tenant take `tenant=""`. A tenant admin's own tenant is
implied; the system admin names one, or leaves it empty for system scope.

`update_tenant` and `update_pool` read the object first and write back the
merge: the server's `PUT` replaces the whole object, so a partial body would
reset everything it leaves out — for a tenant, its list of admins.

### STS without an access key

`AssumeRoleWithWebIdentity` is unsigned — the token is the proof — so a client
built with only an endpoint can call it; every other method on such a client
raises `ObjectIOError` before sending anything:

```python
sts = Client(endpoint="https://s3.example.com")
creds = sts.assume_role_with_web_identity(role.arn, id_token, "ci-job-42")
s3 = boto3.client("s3", **creds.boto3_kwargs("https://s3.example.com"))
```

A refusal raises `APIError` with the STS error code in `e.code`
(`AccessDenied`, `ExpiredTokenException`, …).

## Errors

```python
from objectio import APIError

try:
    app.create_bucket("ws-1")
except APIError as e:
    if not e.already_exists:
        raise
```

`e.forbidden` on the management API almost always means the credential is
scoped. `e.code` carries the error code of an S3, STS or KMS XML error
(`NoSuchBucket`, `AccessDenied` …); the JSON admin errors have only a message.

## Tests

```bash
pip install -e '.[dev]'
python -m pytest tests -q
```

The signature tests need no server; they are pinned to the same vectors as the
[Go SDK](https://github.com/object-io/objectio-go-sdk), because two
implementations of one algorithm drift silently. The request-shape tests run
against a local stub.

`tests/test_integration.py` runs against a real gateway, and is skipped unless
`OBJECTIO_ENDPOINT`, `OBJECTIO_ACCESS_KEY` and `OBJECTIO_SECRET_KEY` (a system
admin) are set. `objectio-aio --auth` is enough; it writes the admin
credential to `<data>/meta/admin-creds.env`.

---

**This repository is generated.** It is mirrored from `sdk/python/` in
[object-io/objectio](https://github.com/object-io/objectio) on every push to
`main`. Open issues and pull requests there — changes made here are overwritten.
