# ObjectIO management SDKs

Clients for the ObjectIO **management API** — everything under `/_admin/*`,
plus STS: tenants and their admins, users and access keys, IAM policies,
groups and roles, identity providers, temporary credentials from an OIDC
token, Block Public Access, buckets, pools, nodes, KMS, warehouses, usage
and metrics.

They deliberately do **not** do S3 data operations. Use the S3 SDK you already
have — aws-sdk-go-v2, boto3, mountpoint-s3, s3fs, rclone — pointed at the same
endpoint with a credential these mint or obtain.

| | install | mirrored to |
|---|---|---|
| `go/` | `go get github.com/object-io/objectio-go-sdk` | [object-io/objectio-go-sdk](https://github.com/object-io/objectio-go-sdk) |
| `python/` | `pip install objectio-sdk` | [object-io/objectio-python-sdk](https://github.com/object-io/objectio-python-sdk) |

The Python distribution is **`objectio-sdk`** because `objectio` is taken on
PyPI by an unrelated package, last touched in 2020. The import is still
`objectio`.

**Source of truth is here.** Each SDK gets a repo of its own because each is
published on its own: for Go that means a clean import path and plain `v0.1.0`
tags — a module nested in a subdirectory has to be tagged `sdk/go/v0.1.0`,
which is the most common way nested modules fail to publish — and for Python
it gives the package a home and a build context for the PyPI upload.
`sdk-go-mirror.yml` and `sdk-python-mirror.yml` copy each directory out on
every push to `main`; edits made in a mirror are overwritten.

Both sign with SigV4 on the standard library alone, so neither adds a
dependency — which matters when this goes into a CSI driver or an operator.
The two implementations are pinned to the same signature vectors
(`sdk/go/sigv4_test.go`, `sdk/python/tests/test_sigv4.py`) so they cannot
drift apart. Method names match across the two: Go `CreatePolicy` is Python
`create_policy`.

## What's covered

| area | Go | Python |
|---|---|---|
| tenants, tenant admins | `CreateTenant`, `UpdateTenant`, `AddTenantAdmin`, … | `create_tenant`, `update_tenant`, `add_tenant_admin`, … |
| users, keys | `CreateUser`, `SuspendUser`, `CreateAccessKey`, `DeactivateAccessKey`, … | `create_user`, `suspend_user`, `create_access_key`, `deactivate_access_key`, … |
| policies | `CreatePolicy`, `AttachPolicy`, `ListAttachedPolicies`, … | `create_policy`, `attach_policy`, `list_attached_policies`, … |
| groups, roles | `CreateGroup`, `AddGroupMember`, `CreateRole`, … | `create_group`, `add_group_member`, `create_role`, … |
| identity providers | `PutOIDCProvider`, `TenantOIDCProviderName`, … | `put_oidc_provider`, `tenant_oidc_provider_name`, … |
| STS | `AssumeRoleWithWebIdentity` | `assume_role_with_web_identity` |
| public access | `PutPublicAccessBlock`, `PutBucketPublicAccessBlock`, `GetBucketPolicyStatus` | `put_public_access_block`, `put_bucket_public_access_block`, `get_bucket_policy_status` |
| buckets | `CreateBucket`, `PutBucketPolicy`, `ProvisionBucket`, … | `create_bucket`, `put_bucket_policy`, `provision_bucket`, … |
| cluster | `ClusterInfo`, `ListNodes`, `ListPools`, `SetOSDAdminState`, `Usage`, `MetricsQuery`, … | `cluster_info`, `list_nodes`, `list_pools`, `set_osd_admin_state`, `usage`, `metrics_query`, … |
| KMS, warehouses, config | `ListKMSKeys`, `CreateWarehouse`, `SetConfig`, … | `list_kms_keys`, `create_warehouse`, `set_config`, … |

IAM objects come back typed; large operational shapes (cluster info, nodes,
topology, usage, metrics) come back as raw JSON. Every call that acts in a
tenant takes an optional tenant: a tenant admin's own is implied, the system
admin names one. See [Identity and Access] and [Public Access] in the docs
for what each object means.

[Identity and Access]: https://github.com/object-io/objectio-docs/blob/main/operations-guide/administration/iam.md
[Public Access]: https://github.com/object-io/objectio-docs/blob/main/operations-guide/administration/public-access.md

## Configuration

Both read the environment, which is how a deployed provisioner is configured:

| | |
|---|---|
| `OBJECTIO_ENDPOINT` or `OBJECTIO_URL` | gateway base URL — **required** |
| `OBJECTIO_ACCESS_KEY` or `OBJECTIO_ACCESS_KEY_FILE` or `AWS_ACCESS_KEY_ID` | |
| `OBJECTIO_SECRET_KEY` or `OBJECTIO_SECRET_KEY_FILE` or `AWS_SECRET_ACCESS_KEY` | |
| `OBJECTIO_REGION` or `AWS_REGION` or `AWS_DEFAULT_REGION` | default `us-east-1` |
| `OBJECTIO_PROVISIONER_USER_ID` | the user per-bucket keys are minted on (see below) |

```go
app, err := objectio.NewFromEnv()
```
```python
app = Client.from_env()
```

The AWS names are fallbacks so one set of variables configures this client and
the S3 SDK beside it — a pod that already has `AWS_ACCESS_KEY_ID` for
mountpoint-s3 needs nothing extra. The `OBJECTIO_*` names win when both are set.

**Prefer the `_FILE` forms in Kubernetes.** A secret in the environment is
readable from `/proc`, lands in crash dumps, and shows up in `kubectl describe
pod` when it was set inline rather than from a `secretRef`. File contents are
stripped — a projected Secret ends in a newline, and a `\n` inside a signing
key produces a `SignatureDoesNotMatch` that reads like a wrong password.

```yaml
apiVersion: v1
kind: Secret
metadata: { name: objectio-provisioner }
stringData:
  access-key: AKIA…
  secret-key: …
---
# in the pod spec
env:
  - name: OBJECTIO_URL
    value: https://s3.example.com
  - name: OBJECTIO_ACCESS_KEY_FILE
    value: /var/run/objectio/access-key
  - name: OBJECTIO_SECRET_KEY_FILE
    value: /var/run/objectio/secret-key
  - name: OBJECTIO_PROVISIONER_USER_ID
    value: 97817a81-…
volumeMounts:
  - name: objectio-creds
    mountPath: /var/run/objectio
    readOnly: true
volumes:
  - name: objectio-creds
    secret:
      secretName: objectio-provisioner
```

The credential must be **unscoped** — a key confined to a bucket is refused on
the management API, which is exactly what stops a credential handed to a workload from
minting itself a wider one.

## A tenant with its own identity provider

As the system admin, once:

```python
from objectio import Client, PublicAccessBlock, tenant_oidc_provider_name

root = Client(endpoint=E, access_key=ADMIN_AK, secret_key=ADMIN_SK)
root.create_tenant("acme", display_name="Acme")
admin = root.create_user("acme-admin", tenant="acme")
root.add_tenant_admin("acme", admin.user_id)
key = root.create_access_key(admin.user_id)          # hand to acme's admin
```

As acme's admin — its IdP, a policy, and a role its CI can assume:

```python
acme = Client(endpoint=E, access_key=key.access_key_id, secret_key=key.secret_access_key)
acme.put_oidc_provider(tenant_oidc_provider_name("acme"), {
    "issuer_url": "https://keycloak.acme.example/realms/acme",
    "client_id": "objectio", "claim_name": "groups",
})
acme.create_policy("data-rw", {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": "s3:*",
    "Resource": ["arn:aws:s3:::acme-data", "arn:aws:s3:::acme-data/*"]}]})
role = acme.create_role("ci", {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "https://keycloak.acme.example/realms/acme"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"ForAnyValue:StringEquals": {
        "keycloak.acme.example/realms/acme:groups": "ci"}}}]})
acme.attach_policy("data-rw", role_name="ci")
```

In CI — no stored credential at all, only the job's OIDC token:

```python
sts = Client(endpoint=E)                              # no keys: STS only
creds = sts.assume_role_with_web_identity(role.arn, token, "build-42")

import boto3
s3 = boto3.client("s3", **creds.boto3_kwargs(E))
```

```go
sts, _ := objectio.New(objectio.Config{Endpoint: e})   // no keys: STS only
creds, err := sts.AssumeRoleWithWebIdentity(ctx, objectio.AssumeRoleWithWebIdentityInput{
    RoleArn: roleArn, WebIdentityToken: token, RoleSessionName: "build-42",
})
```

## Public access

New buckets start blocked. Block a whole tenant (or, as the system admin,
the cluster) so no bucket beneath can be made public:

```python
acme.put_public_access_block(PublicAccessBlock.all_blocked())
```

```go
_, err := acme.PutPublicAccessBlock(ctx, "", objectio.BlockAll, nil)
```

## A bucket and a key confined to it

The quickest way to give an app its own storage — a CSI driver or a platform
operator provisioning on demand. The provisioner is a tenant admin holding
one unscoped key (`OBJECTIO_PROVISIONER_USER_ID` names its user):

```
the provisioner, per app
  ├─ POST /_admin/buckets                     → bucket app-1, owned by the provisioner
  └─ POST /_admin/users/{prov}/access-keys    → key scoped to s3://app-1/
                                                 ↓
                                        handed to the app
```

Two calls, no bucket policy, no extra user per app. It works because the
provisioner **owns** the bucket it just created — with no policy attached
ObjectIO authorizes on ownership — and the scope narrows that ownership down
to the one bucket. The key cannot reach another app's bucket, and cannot be
used against the management API at all.

```go
ba, err := app.ProvisionBucket(ctx, objectio.ProvisionBucketInput{
    Bucket:            "app-1",
    ProvisionerUserID: provisionerUserID,
})
// ba.AccessKeyID / ba.SecretKey are confined to s3://app-1/
```

```python
ba = app.provision_bucket("app-1", provisioner_user_id=provisioner_user_id)
s3 = boto3.client("s3", **ba.boto3_kwargs("https://s3.example.com"))

new = app.rotate_bucket_key(prov.user_id, "app-1")     # old key still valid
app.delete_access_key(old_key_id)                       # cut over when ready
app.deprovision_bucket(prov.user_id, "app-1")           # revoke keys, drop bucket
```

`deprovision_bucket` does not delete objects — the bucket must already be
empty. Losing an app's data should take more than one call.

## Errors

Both surface the status code so a provisioner can be idempotent:

```python
try:
    app.create_bucket("app-1")
except APIError as e:
    if not e.already_exists:
        raise
```

```go
if err := app.CreateBucket(ctx, "app-1", ""); err != nil && !objectio.IsAlreadyExists(err) {
    return err
}
```

## Tests

```
cd sdk/go     && go test ./...
cd sdk/python && python -m pytest tests -q
```

CI runs both on every pull request touching `sdk/`
(`.github/workflows/sdk-ci.yml`), including an assertion that neither has
picked up a dependency.

The signature tests need no server. The `example` program does.
