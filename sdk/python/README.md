# objectio — ObjectIO management API client

Python client for the `/_admin/*` surface: tenants, users, access keys,
buckets and bucket policies. Not an S3 client — use boto3 for data, with a
credential this mints.

See [../README.md](../README.md) for the full walkthrough.

```python
from objectio import Client

app = Client.from_env()          # OBJECTIO_URL / OBJECTIO_ACCESS_KEY[_FILE] / …
# or explicitly:
app = Client(endpoint="https://s3.example.com",
             access_key="AKIA…", secret_key="…")
ws = app.provision_workspace("ws-1", provisioner_user_id=uid)

import boto3
s3 = boto3.client("s3", **ws.boto3_kwargs("https://s3.example.com"))
```

No dependencies: SigV4 is implemented on the standard library.
