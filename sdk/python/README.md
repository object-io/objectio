# objectio-sdk

Python client for the **ObjectIO management API** — the `/_admin/*` surface
that creates tenants, users, access keys, buckets and bucket policies.

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

```python
ws = app.provision_workspace("ws-1", provisioner_user_id=provisioner_user_id)

import boto3
s3 = boto3.client("s3", **ws.boto3_kwargs("https://s3.example.com"))
s3.put_object(Bucket=ws.bucket, Key="hello.txt", Body=b"hi")
```

Two calls, no bucket policy and no extra user: the provisioner owns the bucket
it just created — with no policy attached ObjectIO authorizes on ownership —
and the scope narrows that to the one bucket.

`rotate_workspace_key` mints a replacement while the old key still works;
`deprovision_workspace` revokes the keys and drops the bucket, but will not
delete objects — losing a workspace's data should take more than one call.

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
scoped.

## Tests

```bash
pip install -e '.[dev]'
python -m pytest tests -q
```

The signature tests need no server; they are pinned to the same vectors as the
[Go SDK](https://github.com/object-io/objectio-go-sdk), because two
implementations of one algorithm drift silently.

---

**This repository is generated.** It is mirrored from `sdk/python/` in
[object-io/objectio](https://github.com/object-io/objectio) on every push to
`main`. Open issues and pull requests there — changes made here are overwritten.
