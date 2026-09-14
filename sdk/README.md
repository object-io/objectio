# ObjectIO management SDKs

Clients for the ObjectIO **management API** — the `/_admin/*` surface that
creates tenants, users, access keys, buckets and bucket policies.

They deliberately do **not** do S3 data operations. Use the S3 SDK you already
have — aws-sdk-go-v2, boto3, mountpoint-s3, s3fs, rclone — pointed at the same
endpoint with a credential these mint. The handoff is one call.

| | |
|---|---|
| `go/` | Go module `github.com/object-io/objectio/sdk/go` |
| `python/` | Package `objectio`, Python ≥ 3.9 |

Both sign with SigV4 on the standard library alone, so neither adds a
dependency — which matters when this goes into a CSI driver or an operator.
The two implementations are pinned to the same signature vectors
(`sdk/go/objectio/sigv4_test.go`, `sdk/python/tests/test_sigv4.py`) so they
cannot drift apart.

## The shape this is built for

One bucket per workspace, inside one tenant, with a credential confined to it
that the workspace's app holds:

```
you, once, as system admin
  └─ tenant "platform"
       └─ user "csi-provisioner"  ← a tenant admin; holds ONE unscoped key

the provisioner, per workspace
  ├─ POST /_admin/buckets                     → bucket ws-1, owned by the provisioner
  └─ POST /_admin/users/{prov}/access-keys    → key scoped to s3://ws-1/
                                                 ↓
                                        handed to the workload
```

Two calls, no bucket policy, no extra user per workspace. It works because the
provisioner **owns** the bucket it just created — with no policy attached
ObjectIO authorizes on ownership — and the scope narrows that ownership down
to the one bucket.

The workspace credential cannot reach another workspace's bucket, and cannot
be used against the management API at all: a scoped key is refused there by
design, so a credential handed to a workload can never mint itself a wider
one.

## Go

```go
import "github.com/object-io/objectio/sdk/go/objectio"

app, _ := objectio.New(objectio.Config{
    Endpoint:  "https://s3.example.com",
    AccessKey: provisionerKey,   // must be unscoped
    SecretKey: provisionerSecret,
})

ws, err := app.ProvisionWorkspace(ctx, objectio.ProvisionWorkspaceInput{
    Bucket:            "ws-1",
    ProvisionerUserID: provisionerUserID,
})
// ws.AccessKeyID / ws.SecretKey are confined to s3://ws-1/
```

Hand it to the S3 client:

```go
cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        ws.AccessKeyID, ws.SecretKey, "")))
s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("https://s3.example.com")
    o.UsePathStyle = true
})
```

Run the walkthrough against a live server:

```
go run ./example -endpoint http://127.0.0.1:9000 -access-key AKIA… -secret-key …
```

## Python

```python
from objectio import Client

app = Client(endpoint="https://s3.example.com",
             access_key=provisioner_key,      # must be unscoped
             secret_key=provisioner_secret)

ws = app.provision_workspace("ws-1", provisioner_user_id=provisioner_user_id)

import boto3
s3 = boto3.client("s3", **ws.boto3_kwargs("https://s3.example.com"))
s3.put_object(Bucket=ws.bucket, Key="hello.txt", Body=b"hi")
```

## Bootstrapping the provisioner

Once, with the system admin credential:

```python
root = Client(endpoint=E, access_key=ADMIN_AK, secret_key=ADMIN_SK)
root.create_tenant("platform", display_name="Platform")
prov = root.create_user("csi-provisioner", tenant="platform")
root.add_tenant_admin("platform", prov.user_id)          # ← makes it a provisioner
key = root.create_access_key(prov.user_id)               # ← the one secret it holds
```

That credential can create buckets, users and keys **inside `platform` only**.
It cannot create pools or tenants, list nodes, read cluster config, or touch
another tenant.

## Rotation and teardown

```python
new = app.rotate_workspace_key(prov.user_id, "ws-1")   # old key still valid
app.delete_access_key(old_key_id)                      # cut over when ready

app.deprovision_workspace(prov.user_id, "ws-1")        # revoke keys, drop bucket
```

`deprovision_workspace` does not delete objects — the bucket must already be
empty. Losing a workspace's data should take more than one call.

## When you need a bucket policy

The two-call flow covers "the app reaches the bucket". If a workspace's *own*
users must reach it with their own identities, grant them explicitly:

```python
app.put_bucket_policy("ws-1", {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"OBIO": ["arn:objectio:iam::platform:user/analyst"]},
        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "Resource": ["arn:obio:s3:::ws-1", "arn:obio:s3:::ws-1/*"],
    }],
})
```

No policy does not mean open — it means owner-only.

## Errors

Both surface the status code so a provisioner can be idempotent:

```python
try:
    app.create_bucket("ws-1")
except APIError as e:
    if not e.already_exists:
        raise
```

```go
if err := app.CreateBucket(ctx, "ws-1", ""); err != nil && !objectio.IsAlreadyExists(err) {
    return err
}
```

## Tests

```
cd sdk/go     && go test ./...
cd sdk/python && python -m pytest tests -q
```

The signature tests need no server. The `example` program does.
