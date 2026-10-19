# Security policy

## Reporting a vulnerability

**Don't open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/object-io/objectio/security/advisories/new).
Only the maintainers see it.

Please include what you found, the release (`objectio-gateway --version`,
or the image tag), how it is deployed, and the steps or a proof of
concept that shows it. If you have a fix in mind, describe it in the
report rather than opening a pull request.

What to expect:

- an acknowledgement within 3 working days, and an assessment (whether we
  reproduce it, and how severe we think it is) within 10;
- a fix in a patch release, and a GitHub security advisory (with a CVE
  where one applies) published with it, crediting you unless you'd rather
  not be named;
- we ask that you keep it private until the fix is out, and we'll agree a
  date with you; 90 days from the report at the latest.

## Supported releases

Fixes go into the latest release line. Before 1.0 that is the newest
`0.x` release only: upgrade to it to get a fix.

| Release | Security fixes |
|---|---|
| 0.1.x | Yes |
| Older | No |

## In scope

Anything that lets someone read, change or delete data they shouldn't,
or take the service down from outside: authentication (SigV4, STS, OIDC),
authorization (IAM and bucket policies, tenant isolation, Block Public
Access), encryption (SSE, KMS, TLS and mTLS between services), the admin
API and console, and data loss or corruption that a client can cause.

A deployment that exposes the admin API or meta to the internet, or runs
with `--no-auth`, isn't a vulnerability in ObjectIO; we still want to
hear about defaults that make such a mistake easy.
