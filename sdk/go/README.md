# objectio-go-sdk

Go client for the **ObjectIO management API** — the `/_admin/*` surface that
manages tenants, users and access keys, buckets and their policies, IAM
policies, groups and roles, identity providers, Block Public Access, and the
cluster itself — plus the STS call that turns an OIDC token into temporary
credentials.

```bash
go get github.com/object-io/objectio-go-sdk
```

```go
import "github.com/object-io/objectio-go-sdk"
```

It deliberately does **not** do S3 data operations. Use aws-sdk-go-v2 (or
mountpoint-s3, s3fs, rclone) for those, pointed at the same endpoint with a
credential this mints. The few S3-API calls it does make — a bucket's own
public access block and policy status — are configuration, not data.

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
| `OBJECTIO_PROVISIONER_USER_ID` | the user bucket keys are minted on |

Prefer the `_FILE` forms in Kubernetes — that is how a Secret is projected, and
a secret in the environment is readable from `/proc` and lands in crash dumps.
File contents are trimmed: a projected Secret ends in a newline, and a `\n`
inside a signing key produces a `SignatureDoesNotMatch` that reads like a wrong
password.

The credential must be **unscoped**. A key confined to a bucket is refused on
the management API — which is what stops a credential handed to a workload from
minting itself a wider one.

## Provision a bucket

One bucket per consumer, and one credential confined to it:

```go
ba, err := app.ProvisionBucket(ctx, objectio.ProvisionBucketInput{
    Bucket:            "app-1",
    ProvisionerUserID: provisionerUserID,
})
// ba.AccessKeyID / ba.SecretKey reach s3://app-1/ and nothing else
```

Two calls, no bucket policy and no extra user: the provisioner owns the bucket
it just created — with no policy attached ObjectIO authorizes on ownership —
and the scope narrows that to the one bucket.

Hand it to the S3 client:

```go
cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        ba.AccessKeyID, ba.SecretKey, "")))
s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String(endpoint)
    o.UsePathStyle = true
})
```

`RotateBucketKey` mints a replacement while the old key still works;
`DeprovisionBucket` revokes the keys and drops the bucket, but will not
delete objects — losing a bucket's data should take more than one call.

## Tenants: pass one, or don't

Every IAM call takes a `tenant`. A tenant admin passes `""` and acts in its
own tenant (naming another is refused); the system admin passes the tenant it
means, or `""` for system scope. Names are per tenant, so `acme` and `globex`
can each have a policy called `readers`.

```go
doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[...]}`)
app.CreatePolicy(ctx, "readers", doc, "", false)
app.AttachPolicy(ctx, "readers", objectio.PolicyTarget{UserID: uid}, "")
g, _ := app.CreateGroup(ctx, "devs", "")
app.AddGroupMember(ctx, g.GroupID, uid)
```

`UpdateTenant` and `UpdatePool` take a function and do read-modify-write,
because the server replaces those objects whole — a field a PUT leaves out is
reset, not kept:

```go
root.UpdateTenant(ctx, "acme", func(t *objectio.Tenant) { t.QuotaBytes = 1 << 40 })
```

## Roles and STS

A workload with an OIDC token (a Kubernetes service account, a CI job)
exchanges it for a role's temporary credentials. The call is unsigned — the
token is the proof — so the client needs no keys:

```go
sts, _ := objectio.New(objectio.Config{Endpoint: endpoint})
creds, err := sts.AssumeRoleWithWebIdentity(ctx, objectio.AssumeRoleWithWebIdentityInput{
    RoleArn:          "arn:obio:iam::acme:role/ci",
    WebIdentityToken: token,
    RoleSessionName:  "build-42",
})
// creds.AccessKeyID / SecretAccessKey / SessionToken, until creds.Expiration
```

Any other method on a keyless client returns `ErrNoCredentials`. A tenant's
roles trust only the tenant's own identity provider,
`TenantOIDCProviderName(tenant)` (`t-<tenant>`), which its tenant admin can
create with `PutOIDCProvider`. Reads return the client secret as `********`,
so set it again before writing a provider back.

## Errors

Non-2xx answers are `*objectio.APIError` with the status code. The S3 and STS
calls answer with XML error documents, and their code lands in `Code`:

```go
_, err := app.GetBucketPublicAccessBlock(ctx, "app-1")
var ae *objectio.APIError
if errors.As(err, &ae) && ae.Code == "NoSuchPublicAccessBlockConfiguration" { … }
```

`IsNotFound`, `IsForbidden` and `IsAlreadyExists` cover the common cases.

## What's here

| | |
|---|---|
| tenants | `CreateTenant` `GetTenant` `ListTenants` `UpdateTenant` `DeleteTenant` `AddTenantAdmin` `RemoveTenantAdmin` |
| users | `CreateUser` `GetUser` `ListUsers` `UpdateUser` `SuspendUser` `ActivateUser` `DeleteUser` |
| access keys | `CreateAccessKey` `ListAccessKeys` `UpdateAccessKey` `DeactivateAccessKey` `ActivateAccessKey` `DeleteAccessKey` |
| buckets | `CreateBucket` `ListBuckets` `DeleteBucket` `SetBucketOwner` `Get/Put/DeleteBucketPolicy` `Get/Set/DeleteBucketDedup` |
| provisioning | `ProvisionBucket` `RotateBucketKey` `DeprovisionBucket` |
| IAM policies | `ListPolicies` `CreatePolicy` `GetPolicy` `UpdatePolicy` `DeletePolicy` `AttachPolicy` `DetachPolicy` `ListAttachedPolicies` |
| groups | `ListGroups` `CreateGroup` `GetGroup` `DeleteGroup` `AddGroupMember` `RemoveGroupMember` |
| roles, STS | `ListRoles` `CreateRole` `GetRole` `UpdateRole` `DeleteRole` `AssumeRoleWithWebIdentity` |
| identity providers | `ListOIDCProviders` `GetOIDCProvider` `PutOIDCProvider` `DeleteOIDCProvider` `TenantOIDCProviderName` |
| stored config | `ListConfig` `GetConfig` `SetConfig` `DeleteConfig` |
| Block Public Access | `Get/Put/DeletePublicAccessBlock` (tenant, cluster) · `Get/Put/DeleteBucketPublicAccessBlock` `GetBucketPolicyStatus` (bucket) |
| cluster | `ClusterInfo` `ListNodes` `Topology` `Usage` `DrainStatus` `RebalanceStatus` `PauseRebalance` `ResumeRebalance` `SetOSDAdminState` |
| pools | `ListPools` `CreatePool` `GetPool` `UpdatePool` `DeletePool` `ListPlacementGroups` |
| KMS, Iceberg, metrics | `KMSStatus` `ListKMSKeys` `CreateKMSKey` `GetKMSKey` · `ListWarehouses` `CreateWarehouse` `DeleteWarehouse` · `MetricsQuery` `MetricsQueryRange` |

IAM objects, pools, keys and warehouses come back typed. The cluster reports,
dedup reports, placement groups and metrics come back as `json.RawMessage`:
they are large, grow fields between releases, and are for reading rather than
editing.

## Run the walkthrough

```bash
go run ./example -endpoint http://127.0.0.1:9000 -access-key AKIA… -secret-key …
# or with no flags, from the environment
```

## Tests

```bash
go test ./...                                   # no server needed
OBJECTIO_ENDPOINT=http://127.0.0.1:9000 OBJECTIO_ACCESS_KEY=… OBJECTIO_SECRET_KEY=… \
  go test -tags integration ./...               # against a live gateway, as system admin
```

The integration test names everything with a per-run suffix and removes it
afterwards. It does set the cluster-wide public access block, and leaves it
unset.

---

**This repository is generated.** It is mirrored from `sdk/go/` in
[object-io/objectio](https://github.com/object-io/objectio) on every push to
`main`. Open issues and pull requests there — changes made here are overwritten.
