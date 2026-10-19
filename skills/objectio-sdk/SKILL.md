---
name: objectio-sdk
description: Build applications on ObjectIO, the S3-compatible object store — connect boto3, the AWS CLI or aws-sdk-go-v2 (endpoint, path-style addressing, region, SigV4), get credentials right (a bucket-scoped key from provisioning, temporary keys from an OIDC token via STS, the env vars the SDKs read), know which S3 features exist (multipart, presigned URLs, versioning, Object Lock, SSE-S3/KMS/C, Select, lifecycle) and which are refused (ACLs, SigV2, website), handle errors and retries, and use the objectio-sdk (Python) and objectio-go-sdk (Go) management clients for provisioning, IAM, STS, OIDC, public access and audit, with pointers to the Iceberg REST catalog and Delta Sharing. Use when writing or debugging code that stores or reads objects on ObjectIO, when a client gets SignatureDoesNotMatch, AccessDenied, 413 or an empty listing it should not, when an app needs its own bucket and key, or when wiring pyiceberg or a Delta Sharing client to ObjectIO.
---

# ObjectIO for application code

ObjectIO speaks S3, so store and read objects with the S3 client you already
use. ObjectIO's own SDKs cover what S3 does not: a bucket with its own key,
IAM, STS, identity providers, public access, audit. Running a cluster is
[objectio-deploy](../objectio-deploy/SKILL.md). Managing tenants, users and
policies as an operator is [objectio-admin](../objectio-admin/SKILL.md).

## Connecting

One base URL (port 9000 by default) serves S3, STS, the IAM API, Iceberg,
Delta Sharing and the admin API. If the operator gave the admin API its own
port, only the management SDKs point there.

- **Path-style only.** The gateway has no virtual-hosted routing. A request
  to `bucket.s3.example.com` arrives as `GET /` and is answered as
  ListBuckets, so a listing comes back empty instead of failing.
- **Region** must match the gateway's `--region` (default `us-east-1`).
  Any other region gets `SignatureDoesNotMatch`.
- **SigV4 only.** SigV2 gets `400 InvalidRequest`. boto3 and AWS CLI v1
  still presign with SigV2 against a custom endpoint unless told otherwise.

```python
import boto3
from botocore.config import Config

cfg = Config(signature_version="s3v4", s3={"addressing_style": "path"},
             retries={"mode": "standard", "max_attempts": 5})
s3 = boto3.client("s3", endpoint_url="https://s3.example.com",
                  region_name="us-east-1", config=cfg)
s3.put_object(Bucket="app-1", Key="hello.txt", Body=b"hi")
```

```go
cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk, "")))
s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("https://s3.example.com")
    o.UsePathStyle = true
})
```

```bash
export AWS_ENDPOINT_URL=https://s3.example.com AWS_DEFAULT_REGION=us-east-1
aws configure set default.s3.addressing_style path
aws configure set default.s3.signature_version s3v4   # or `aws s3 presign` signs SigV2
aws s3 cp ./report.pdf s3://app-1/reports/
```

## Credentials

Give an app the narrowest credential that works: best **a key scoped to its
bucket** from a provisioner, then **temporary keys from STS** for an OIDC
token it already has (a Kubernetes service account, a CI job), then **a
user's key** with policies an admin set. Never an admin or shared unscoped key.

S3 clients use their usual chain: arguments, then `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` (and `AWS_ENDPOINT_URL`), then
`~/.aws`. The management SDKs (`Client.from_env()`, `objectio.NewFromEnv()`)
take the first variable set:

| setting | read from, in order |
|---|---|
| endpoint (required) | `OBJECTIO_ENDPOINT`, `OBJECTIO_URL` |
| access key | `OBJECTIO_ACCESS_KEY_FILE`, `OBJECTIO_ACCESS_KEY`, `AWS_ACCESS_KEY_ID` |
| secret key | `OBJECTIO_SECRET_KEY_FILE`, `OBJECTIO_SECRET_KEY`, `AWS_SECRET_ACCESS_KEY` |
| region | `OBJECTIO_REGION`, `AWS_REGION`, `AWS_DEFAULT_REGION`, else `us-east-1` |
| provisioner user | `OBJECTIO_PROVISIONER_USER_ID`, via `provisioner_user_id_from_env()` / `ProvisionerUserIDFromEnv()` |

`_FILE` contents are trimmed. Prefer the `_FILE` forms in Kubernetes,
because a secret in the environment shows in `/proc` and crash dumps. The
SDKs sign with a long-lived key only: no session token, no `~/.aws` files.

### A bucket and a key confined to it

The provisioner is a tenant admin holding one unscoped key. It creates the
bucket, so it owns it, and mints a key on itself scoped to that bucket. That
takes two calls, with no bucket policy and no extra user.

```python
from objectio import Client
admin = Client.from_env()                                       # the provisioner
ba = admin.provision_bucket("app-1", provisioner_user_id=uid)   # also prefix="in/", read_only=True
s3 = boto3.client("s3", config=cfg, **ba.boto3_kwargs("https://s3.example.com"))
```

```go
ba, err := app.ProvisionBucket(ctx, objectio.ProvisionBucketInput{
    Bucket: "app-1", ProvisionerUserID: objectio.ProvisionerUserIDFromEnv(),
})
// ba.AccessKeyID / ba.SecretKey reach s3://app-1/ and nothing else
```

A scoped key reaches only its bucket or prefix. Another bucket, or
CreateBucket, gets `AccessDenied`. ListBuckets shows only its own bucket. A
read-only key is refused every write. On the management API it gets `403`,
so it cannot mint itself a wider key. To rotate, call
`rotate_bucket_key(uid, "app-1")` (Go: `RotateBucketKey`). The old key works
until `delete_access_key(old_id)`, so a rollout can overlap.
`deprovision_bucket` revokes the keys and deletes the bucket, but only an
empty one.

### Temporary keys from an OIDC token (STS)

`AssumeRoleWithWebIdentity` is unsigned, because the token is the proof. The
client needs only the endpoint. A tenant admin sets up the role, its trust
policy and the tenant's identity provider (see objectio-admin).

```python
creds = Client(endpoint=E).assume_role_with_web_identity(
    "arn:obio:iam::acme:role/ci", id_token, "build-42")       # duration_seconds=3600
s3 = boto3.client("s3", config=cfg, **creds.boto3_kwargs(E))   # includes the session token
```

```go
sts, _ := objectio.New(objectio.Config{Endpoint: endpoint})    // no keys: STS only
creds, err := sts.AssumeRoleWithWebIdentity(ctx, objectio.AssumeRoleWithWebIdentityInput{
    RoleArn: "arn:obio:iam::acme:role/ci", WebIdentityToken: token, RoleSessionName: "build-42",
})
```

boto3's own `sts.assume_role_with_web_identity` works too, pointed at the
same endpoint. All three parts are needed: key, secret and session token.
They last 900 s up to the role's `max_session_seconds` (1 hour by default,
12 hours at most). Exchange the token again before `creds.expiration`.
Refusals: `AccessDenied` (no matching trust policy, or no such role, answered
alike), `InvalidIdentityToken` (a provider the role does not trust),
`ExpiredTokenException`, `ValidationError`.

## What S3 does here

Supported, as AWS does it:

- Buckets and objects, DeleteObjects, ListObjectsV2, ranges, copy,
  UploadPartCopy, `x-amz-meta-*`, tagging, checksums.
- Conditional writes, applied atomically: `IfNoneMatch="*"` (create only,
  else `412`) and `IfMatch=etag` (compare-and-swap).
- **Multipart**, up to 10,000 parts. A single PUT, and each part, is at
  most **100 MiB**. Anything larger gets `413`. The 8 MiB defaults of boto3
  and the CLI are fine. Above about 80 GB, raise `multipart_chunksize`, up
  to 100 MiB.
- **Presigned URLs** (SigV4, up to 7 days). **POST Object**
  (`generate_presigned_post`) for browser uploads. CORS via `?cors`.
- **Versioning**: delete markers, `VersionId`, ListObjectVersions.
  **Object Lock** on a bucket created with `ObjectLockEnabledForBucket=True`
  or a versioned one (unversioned: `InvalidBucketState`): GOVERNANCE
  (`BypassGovernanceRetention=True` deletes), COMPLIANCE, legal hold. A
  locked delete gets `403 AccessDenied`.
- **Encryption**: SSE-S3 (`ServerSideEncryption="AES256"`) and bucket
  defaults. SSE-KMS needs `SSEKMSKeyId` unless the bucket default names a
  key. SSE-C needs the key on every GET and HEAD, and is refused on a
  CopyObject (`501`) and on a warehouse bucket.
- **S3 Select** on CSV, JSON and Parquet (GZIP or BZIP2 for CSV and JSON),
  with AWS's SQL subset.
- **Lifecycle**: expiration, noncurrent versions, delete markers, and
  aborting incomplete uploads. It acts at the next scan, hourly by default.

Refused, by design; do not build on these. Every ceph s3-tests result is in
the [S3 compatibility](https://object-io.github.io/latest/developer-guide/s3-compatibility/) runs.

| | what you get | do instead |
|---|---|---|
| ACL grants, `public-read`, `x-amz-grant-*` | `AccessControlListNotSupported`; buckets are `BucketOwnerEnforced` | bucket policies |
| SigV2, including old presigned URLs | `400 InvalidRequest` | SigV4 |
| Lifecycle transitions | `InvalidStorageClass` (one storage class) | expiration |
| Website, inventory, analytics, accelerate, request payment, torrent, notifications | `501 NotImplemented` | |
| RGW extensions (`tenant:bucket`, unordered listing, `X-RGW-*`, usage API) | not served | standard S3 |
| Access across tenants | denied before any policy is read | one tenant |

## Consistency and durability

A `200` on a PUT comes only after the shards are flushed to disk, the
metadata is at a quorum of OSDs, and the key is in the bucket's listing
through Raft. A GET, HEAD or LIST after that sees the object, and reads take
the newest copy from a read quorum, never a deleted or overwritten one. So
do not add sleeps, "retry until visible" loops or listing caches: there is
no eventual consistency to work around.

What does take time: key, user and policy changes reach other gateways
within 15 s. Quotas across several gateways can overshoot by about one 5 s
usage report. Lifecycle acts at its next scan. Replication to another
cluster is asynchronous.

## Errors and retries

| answer | meaning | do |
|---|---|---|
| `503 ServiceUnavailable`, `500 InternalError` | transient: replicas unreachable, a clock out of step | retry with backoff (`retries={"mode": "standard"}`) |
| `507 StorageFull` | the cluster's disks are full | do not retry in a loop; tell a human |
| `403 QuotaExceeded` | a tenant or bucket quota | free space, or ask for more |
| `403 AccessDenied` | scope, policy, Object Lock, public access block | check which key signed, and its scope |
| `403 SignatureDoesNotMatch` | wrong region, wrong secret, a newline in it | `us-east-1` unless told otherwise; trim secrets |
| `400 InvalidRequest` | SigV2 | `signature_version="s3v4"` |
| `413` | body over 100 MiB | multipart |
| `412 PreconditionFailed` | an `If-*` condition failed | an answer, not a fault |

Retrying a PUT is safe, because it overwrites. In a versioned bucket a retry
can leave an extra version. When a write must happen exactly once, send
`IfNoneMatch="*"`. A `412` on the retry then means the first attempt landed.

The management SDKs raise `objectio.APIError` (`status_code`, `code`,
`message`, and `already_exists` / `forbidden` / `not_found`); Go returns
`*objectio.APIError` with `IsAlreadyExists`, `IsForbidden`, `IsNotFound`.
Re-raise unless `e.already_exists` to make a create idempotent. There,
`forbidden` almost always means a scoped key.

## Making objects public

New buckets start blocked, and while `BlockPublicPolicy` holds a public
policy gets `AccessDenied`. The owner lifts the bucket's block, then sets it:

```python
s3.put_public_access_block(Bucket="site-assets", PublicAccessBlockConfiguration={
    "BlockPublicAcls": True, "IgnorePublicAcls": True,
    "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
s3.put_bucket_policy(Bucket="site-assets", Policy=json.dumps({"Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                   "Resource": "arn:aws:s3:::site-assets/*"}]}))
```

A tenant or cluster block still wins (an admin's call). To share one object
for a while, a presigned URL is better.

## The management SDKs

```bash
pip install objectio-sdk                        # import objectio; standard library only
go get github.com/object-io/objectio-go-sdk     # package objectio
```

`Client(endpoint=, access_key=, secret_key=, region="us-east-1", timeout=30.0)`;
Go `objectio.New(objectio.Config{Endpoint, AccessKey, SecretKey, Region, HTTPClient})`.
Neither does S3 data operations: hand what they mint to an S3 client.

| area | Python (Go: the same in CamelCase) |
|---|---|
| provisioning | `provision_bucket`, `rotate_bucket_key`, `deprovision_bucket` |
| buckets | `create_bucket`, `list_buckets`, `get/put/delete_bucket_policy` |
| users, keys | `create_user`, `create_access_key(user_id, scope=, read_only=)`, `deactivate_access_key`, `delete_access_key` |
| IAM | `create_policy`, `attach_policy(name, user_id= / group_id= / role_name=)`, `create_group`, `create_role` |
| OIDC, STS | `put_oidc_provider`, `tenant_oidc_provider_name(tenant)`, `assume_role_with_web_identity` |
| public access | `put_public_access_block`, `put_bucket_public_access_block`, `get_bucket_policy_status` |
| audit | `get_audit_config`, `put_audit_config`, `delete_audit_config` |
| data lake, KMS | `create_warehouse`, `list_warehouses`, `create_kms_key`, `list_kms_keys` |

Every management call needs an **unscoped** key, a provisioner's or an
admin's, which belongs in the provisioning service, not the app. `tenant=""`
means a tenant admin's own tenant. A keyless client can call only STS;
anything else raises `ObjectIOError` (Go: `ErrNoCredentials`) unsent.

## Data lake APIs (previews)

Built and unit-tested, not yet tested with real engines: check a write end
to end before you depend on one.

- **Iceberg REST catalog** at `<endpoint>/iceberg`. `create_warehouse("lake")`
  makes a warehouse backed by bucket `iceberg-lake`. LoadTable vends
  temporary S3 keys for the table. Spark and Trino: the
  [Iceberg guide](https://object-io.github.io/latest/operations-guide/administration/iceberg-api/);
  pyiceberg: `examples/pyiceberg/`.

  ```python
  from pyiceberg.catalog.rest import RestCatalog   # signs with AWS_ACCESS_KEY_ID/SECRET from the env
  cat = RestCatalog("objectio", uri=f"{E}/iceberg", warehouse="lake", **{
      "rest.sigv4-enabled": "true", "rest.signing-name": "s3",
      "rest.signing-region": "us-east-1", "s3.endpoint": E, "s3.path-style-access": "true"})
  cat.create_namespace_if_not_exists("analytics")
  ```
- **Delta Sharing**: a recipient is shown its bearer token once. The
  profile's endpoint is `<endpoint>/delta-sharing/v1`.

  ```python
  # partner.share: {"shareCredentialsVersion": 1, "endpoint": "https://s3.example.com/delta-sharing/v1", "bearerToken": "…"}
  import delta_sharing
  delta_sharing.SharingClient("partner.share").list_all_tables()
  ```
- **Unity Catalog** API at `/api/2.1/unity-catalog/*`, with examples in
  `examples/unity-catalog/`.

## What not to do

- **No admin or unscoped key in an app,** image or repo: it mints keys and
  reaches every bucket in the tenant. Use a scoped key or STS.
- **No ACLs to share data:** they grant nothing. Use policies or presigned URLs.
- **No RGW or MinIO extensions, no virtual-hosted addressing:** refused, or
  worse, silently misread.
- **No consistency workarounds:** an acknowledged write is durable and visible.
- **No secrets in logs:** a secret is shown once, at creation. A lost one is
  replaced, not recovered.

## Further reading

Under https://object-io.github.io/latest/: `developer-guide/` (start here),
`developer-guide/sdk/`, `operations-guide/administration/s3-api/`,
`developer-guide/features/`, `features/` (status of every feature),
`operations-guide/administration/iam/` (IAM, OIDC, STS),
`operations-guide/administration/public-access/`, `how-it-works/`.
Every SDK method is listed in `sdk/python/README.md` and `sdk/go/README.md`.
