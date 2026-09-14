"""ObjectIO management API client.

Covers the ``/_admin/*`` surface: tenants, users, access keys, buckets and
bucket policies. It does **not** do S3 data operations — use boto3 (or
mountpoint-s3, s3fs, rclone …) for those, pointed at the same endpoint with a
credential this package mints:

    from objectio import Client

    admin = Client(endpoint="https://s3.example.com",
                   access_key="AKIA…", secret_key="…")

    ws = admin.provision_workspace("ws-1", provisioner_user_id=uid)

    import boto3
    s3 = boto3.client("s3", **ws.boto3_kwargs("https://s3.example.com"))
    s3.put_object(Bucket=ws.bucket, Key="hello.txt", Body=b"hi")

Requests are signed with SigV4 using the standard library alone, so this
package has no dependencies.
"""

from .client import AccessKey, Bucket, Client, User, Workspace
from .errors import APIError, ObjectIOError

__all__ = [
    "AccessKey",
    "APIError",
    "Bucket",
    "Client",
    "ObjectIOError",
    "User",
    "Workspace",
]
__version__ = "0.1.0"
