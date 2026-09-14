# ObjectIO management SDKs

Clients for the ObjectIO **management API** — the `/_admin/*` surface that
creates tenants, users, access keys, buckets and bucket policies.

They deliberately do **not** do S3 data operations. Use the S3 SDK you already
have — aws-sdk-go-v2, boto3, mountpoint-s3, s3fs, rclone — pointed at the same
endpoint with a credential these mint. The handoff is one call.

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
it gives the package a home and a build context for the PyPI upload. `sdk-go-mirror.yml` and
`sdk-python-mirror.yml` copy each directory out on every push to `main`; edits
made in a mirror are overwritten.

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

## Configuration

Both read the environment, which is how a deployed provisioner is configured:

| | |
|---|---|
| `OBJECTIO_ENDPOINT` or `OBJECTIO_URL` | gateway base URL — **required** |
| `OBJECTIO_ACCESS_KEY` or `OBJECTIO_ACCESS_KEY_FILE` or `AWS_ACCESS_KEY_ID` | |
| `OBJECTIO_SECRET_KEY` or `OBJECTIO_SECRET_KEY_FILE` or `AWS_SECRET_ACCESS_KEY` | |
| `OBJECTIO_REGION` or `AWS_REGION` or `AWS_DEFAULT_REGION` | default `us-east-1` |
| `OBJECTIO_PROVISIONER_USER_ID` | the user workspace keys are minted on |

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
the management API, which is exactly what stops a workspace credential being
used as a provisioner one.

## Go

```go
import "github.com/object-io/objectio-go-sdk"

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

Install it:

```bash
go get github.com/object-io/objectio-go-sdk
```

Run the walkthrough against a live server:

```
cd sdk/go && go run ./example -endpoint http://127.0.0.1:9000 -access-key AKIA… -secret-key …
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

CI runs both on every pull request touching `sdk/`
(`.github/workflows/sdk-ci.yml`), including an assertion that neither has
picked up a dependency.

The signature tests need no server. The `example` program does.
