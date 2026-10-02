# objectio-cli

The ObjectIO management CLI. It is a client of the gateway's admin HTTP API
(`/_admin/*`), signed with SigV4 exactly like the SDKs in `sdk/go` and
`sdk/python`. Every command passes through the gateway's authentication,
tenant scoping, validation, Block Public Access, audit events and cache
invalidation. It never talks to meta directly.

The exceptions:

- Bucket lifecycle, CORS and the bucket-level public access block are S3
  subresources (`/{bucket}?lifecycle`, `?cors`, `?publicAccessBlock`,
  `?policyStatus`), signed the same way.
- `sts assume-role-with-web-identity` is an unsigned STS call, where the
  token is the proof.
- `volume` and `snapshot` speak gRPC to the block gateway's BlockService
  (`--block-endpoint`, default `http://localhost:9300`).

## Configure

```sh
objectio-cli configure                      # prompts; writes profile "default"
objectio-cli --profile acme configure \
  --endpoint https://s3.example.com --access-key AKIA... --secret-key ... --non-interactive
objectio-cli configure --list               # secrets masked
```

Profiles are stored in `~/.objectio/config` (or `$OBJECTIO_CONFIG_FILE`) with
mode 0600:

```toml
[default]
endpoint = "https://s3.example.com"
access_key = "AKIA..."
secret_key = "..."
region = "us-east-1"   # optional
```

Settings are resolved in this order, and the first source that has a value
wins:

1. Flags: `--endpoint`, `--access-key`/`--secret-key`, `--region`.
2. The profile named with `--profile`.
3. The environment, read the same way the SDKs read it:
   - `OBJECTIO_ENDPOINT` or `OBJECTIO_URL`
   - `OBJECTIO_ACCESS_KEY_FILE`, `OBJECTIO_ACCESS_KEY` or `AWS_ACCESS_KEY_ID`
   - `OBJECTIO_SECRET_KEY_FILE`, `OBJECTIO_SECRET_KEY` or `AWS_SECRET_ACCESS_KEY`
   - `OBJECTIO_REGION`, `AWS_REGION` or `AWS_DEFAULT_REGION`
4. The profile named by `OBJECTIO_PROFILE`, else `default`.

The region defaults to `us-east-1`. The access key and secret are always
taken from the same source. Prefer the `_FILE` variables or a profile:
a `--secret-key` flag shows up in the process list.

The credential must be **unscoped**. A key confined to a bucket is refused
by the admin API, by design.

## Tenants

Every tenant-scoped command takes `--tenant`. Without it, the command acts
in the caller's own tenant, which is system scope for the system admin.
An empty `--tenant ""` is rejected rather than sent.

Some endpoints have no tenant parameter: `user list`, `bucket list` and
`warehouse list`. They answer with the caller's tenant, or with everything
for the system admin, and `--tenant` filters that answer on the client.

## Output

Output is a human-readable table by default. With `-o json` (`--output
json`), the CLI prints the API's own JSON document, pretty-printed, so
scripts read the same shapes the SDKs do:

```sh
objectio-cli -o json user create alice | jq -r .user_id
```

Commands that get no response body (HTTP 204), such as deletes, print
nothing in JSON mode. Lifecycle and CORS documents are S3 XML and are
printed as-is in both modes, ready to pass back to `put --file`.

On any error the exit code is non-zero, and stderr carries the server's
own message, for example `error: GET /_admin/tenants/x: 404: Tenant not found`.

Secrets are printed only once, when they are created: by `key create`,
`provision bucket`/`rotate-key` and STS.

## Commands

| command | route |
|---|---|
| `tenant list` / `show N` | `GET /_admin/tenants[/N]` |
| `tenant create N [--display-name --default-pool --allowed-pool --quota-bytes 10G --quota-buckets --quota-objects --oidc-provider --label k=v --disabled]` | `POST /_admin/tenants` |
| `tenant update N [same fields, --enabled]` (only the fields given) | `PUT /_admin/tenants/N` |
| `tenant delete N` | `DELETE /_admin/tenants/N` |
| `tenant admin list T` / `add T USER` / `remove T USER` | `GET /_admin/tenants/T`, `POST /_admin/tenants/T/admins`, `DELETE …/admins/USER` |
| `user list [--tenant]` / `show ID` | `GET /_admin/users[/ID]` |
| `user create NAME [--email --tenant]` | `POST /_admin/users` |
| `user update ID [--display-name --email]` / `suspend ID` / `activate ID` | `PUT /_admin/users/ID` |
| `user delete ID` | `DELETE /_admin/users/ID` |
| `key list USER` | `GET /_admin/users/USER/access-keys` |
| `key create USER [--scope s3://b/p/ --read-only]` | `POST /_admin/users/USER/access-keys` |
| `key activate K` / `deactivate K` | `PUT /_admin/access-keys/K` |
| `key delete K` | `DELETE /_admin/access-keys/K` |
| `policy list` / `show N` / `delete N` `[--tenant]` | `GET`/`DELETE /_admin/policies[/N]` |
| `policy create N --file F [--shared --tenant]` | `POST /_admin/policies` |
| `policy update N --file F [--tenant]` | `PUT /_admin/policies/N` |
| `policy attach` / `detach N --user U \| --group G \| --role R [--tenant]` | `POST /_admin/policies/attach`, `…/detach` |
| `policy attached --user U \| --group G \| --role R [--tenant]` | `GET /_admin/policies/attached` |
| `group list [--tenant]` / `show ID` / `create N [--tenant]` / `delete ID` | `/_admin/groups[/ID]` |
| `group add-user G U` / `remove-user G U` | `POST /_admin/groups/G/members`, `DELETE …/members/U` |
| `role list` / `show N` / `delete N` `[--tenant]` | `/_admin/roles[/N]` |
| `role create N --trust-file F [--description --max-session-seconds --tenant]` | `POST /_admin/roles` |
| `role update N [--trust-file --description --max-session-seconds --tenant]` | `PUT /_admin/roles/N` |
| `oidc list` / `show N` / `put N --file F` / `delete N` | `/_admin/config[/identity/openid/N]` |
| `oidc tenant-name T` | prints `t-<tenant>`; makes no request |
| `sts assume-role-with-web-identity --role-arn A --token T \| --token-file F [--session-name --duration-seconds --env]` | `POST /` (unsigned, STS) |
| `public-access-block get` / `delete` `[--tenant]` | `GET`/`DELETE /_admin/public-access-block` |
| `public-access-block put [--all --block-public-acls --ignore-public-acls --block-public-policy --restrict-public-buckets --new-buckets-blocked B --tenant]` | `PUT /_admin/public-access-block` |
| `public-access-block bucket get` / `put` / `delete B` | `/{B}?publicAccessBlock` |
| `public-access-block bucket policy-status B` | `GET /{B}?policyStatus` |
| `audit get` / `delete` `[--tenant]`, `audit put --file F [--tenant]` | `/_admin/audit` |
| `bucket list [--tenant]` / `show B` | `GET /_admin/buckets` |
| `bucket create B [--pool P --tenant]` / `delete B` | `POST /_admin/buckets`, `DELETE /_admin/buckets/B` |
| `bucket set-owner B USER` | `PUT /_admin/buckets/B/owner` |
| `bucket policy get` / `put --file` / `delete B` | `/_admin/buckets/B/policy` |
| `bucket dedup get` / `set [--mode --scope]` / `delete B` | `/_admin/buckets/B/dedup` |
| `bucket lifecycle get` / `put --file` / `delete B` | `/{B}?lifecycle` (XML) |
| `bucket cors get` / `put --file` / `delete B` | `/{B}?cors` (XML) |
| `provision bucket B --user U [--prefix p/ --read-only --pool --tenant]` | `GET /_admin/users/U`, then `POST /_admin/buckets`, then `POST …/access-keys` (scoped) |
| `provision rotate-key B --user U [--read-only]` | `POST /_admin/users/U/access-keys` |
| `provision deprovision B --user U` | revokes U's keys scoped to B, then `DELETE /_admin/buckets/B` |
| `cluster info` / `topology` / `usage` / `drain-status` | `GET /_admin/cluster-info`, `/topology`, `/usage`, `/drain-status` |
| `cluster validate-placement POOL` | `GET /_admin/placement/validate?pool=` |
| `cluster rebalance status` / `pause` / `resume` | `GET /_admin/rebalance-status`, `POST /_admin/rebalance/{pause,resume}` |
| `node list` / `show ID\|NAME` | `GET /_admin/nodes` |
| `osd set-state ID in\|out\|draining` | `PUT /_admin/osds/ID/admin-state` |
| `pool list` / `show` / `create` / `update` (only the fields given) / `delete` | `/_admin/pools[/N]` |
| `pool placement-groups N [--start-after --max]` | `GET /_admin/pools/N/placement-groups` |
| `kms status`, `kms keys list` / `create [--key-id --description]` / `show K` | `/_admin/kms/status`, `/_admin/kms/keys[/K]` |
| `warehouse list [--tenant]` / `create N [--property k=v --tenant]` / `delete N` | `/_admin/warehouses[/N]` |
| `config list [--prefix]` / `get K` / `set K --value J \| --file F` / `delete K` | `/_admin/config[/K]` |
| `metrics query Q [--time]` / `query-range Q --start --end --step` | `GET /_admin/metrics/query[_range]` |
| `volume …`, `snapshot …` | gRPC `BlockService` at `--block-endpoint` |

For `provision`, `--user` defaults to `$OBJECTIO_PROVISIONER_USER_ID`.

## Examples

Onboard a tenant as the system admin:

```sh
objectio-cli tenant create acme --display-name "Acme Corp" --quota-bytes 2T
ADMIN=$(objectio-cli -o json user create acme-admin --tenant acme | jq -r .user_id)
objectio-cli tenant admin add acme "$ADMIN"
objectio-cli key create "$ADMIN"            # hand this key to the tenant admin
```

Then, as the tenant admin (no `--tenant` needed):

```sh
objectio-cli user create alice
objectio-cli policy create read-logs --file read-logs.json
objectio-cli policy attach read-logs --user <alice-id>
objectio-cli public-access-block put --all
objectio-cli bucket create logs
objectio-cli bucket lifecycle put logs --file lifecycle.xml
objectio-cli provision bucket ws-1 --user "$ADMIN"   # bucket + key scoped to it
```

Get temporary credentials from an OIDC token (no key needed):

```sh
eval "$(objectio-cli sts assume-role-with-web-identity \
  --role-arn arn:obio:iam::acme:role/etl --token-file /var/run/secrets/token --env)"
```
