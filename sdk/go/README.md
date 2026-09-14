# objectio-go-sdk

Go client for the **ObjectIO management API** — the `/_admin/*` surface that
creates tenants, users, access keys, buckets and bucket policies.

```bash
go get github.com/object-io/objectio-go-sdk
```

```go
import "github.com/object-io/objectio-go-sdk"
```

It deliberately does **not** do S3 data operations. Use aws-sdk-go-v2 (or
mountpoint-s3, s3fs, rclone) for those, pointed at the same endpoint with a
credential this mints.

**No dependencies.** SigV4 is implemented on the standard library, so dropping
this into a CSI driver or an operator pulls in nothing else.

## Configure

```go
app, err := objectio.NewFromEnv()
```

| | |
|---|---|
| `OBJECTIO_ENDPOINT` or `OBJECTIO_URL` | gateway base URL — **required** |
| `OBJECTIO_ACCESS_KEY` · `OBJECTIO_ACCESS_KEY_FILE` · `AWS_ACCESS_KEY_ID` | |
| `OBJECTIO_SECRET_KEY` · `OBJECTIO_SECRET_KEY_FILE` · `AWS_SECRET_ACCESS_KEY` | |
| `OBJECTIO_REGION` · `AWS_REGION` · `AWS_DEFAULT_REGION` | default `us-east-1` |
| `OBJECTIO_PROVISIONER_USER_ID` | the user workspace keys are minted on |

Prefer the `_FILE` forms in Kubernetes — that is how a Secret is projected, and
a secret in the environment is readable from `/proc` and lands in crash dumps.
File contents are trimmed: a projected Secret ends in a newline, and a `\n`
inside a signing key produces a `SignatureDoesNotMatch` that reads like a wrong
password.

The credential must be **unscoped**. A key confined to a bucket is refused on
the management API — which is what stops a credential handed to a workload from
minting itself a wider one.

## Provision a workspace

One bucket per workspace, and one credential confined to it:

```go
ws, err := app.ProvisionWorkspace(ctx, objectio.ProvisionWorkspaceInput{
    Bucket:            "ws-1",
    ProvisionerUserID: provisionerUserID,
})
// ws.AccessKeyID / ws.SecretKey reach s3://ws-1/ and nothing else
```

Two calls, no bucket policy and no extra user: the provisioner owns the bucket
it just created — with no policy attached ObjectIO authorizes on ownership —
and the scope narrows that to the one bucket.

Hand it to the S3 client:

```go
cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        ws.AccessKeyID, ws.SecretKey, "")))
s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String(endpoint)
    o.UsePathStyle = true
})
```

`RotateWorkspaceKey` mints a replacement while the old key still works;
`DeprovisionWorkspace` revokes the keys and drops the bucket, but will not
delete objects — losing a workspace's data should take more than one call.

## Run the walkthrough

```bash
go run ./example -endpoint http://127.0.0.1:9000 -access-key AKIA… -secret-key …
# or with no flags, from the environment
```

---

**This repository is generated.** It is mirrored from `sdk/go/` in
[object-io/objectio](https://github.com/object-io/objectio) on every push to
`main`. Open issues and pull requests there — changes made here are overwritten.
