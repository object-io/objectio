"""ObjectIO management API client.

Covers the ``/_admin/*`` surface — tenants, users, access keys, buckets,
bucket policies, IAM policies, groups and roles, identity providers, Block
Public Access, pools, KMS and cluster status — plus STS
``AssumeRoleWithWebIdentity``. It does **not** do S3 data operations — use
boto3 (or mountpoint-s3, s3fs, rclone …) for those, pointed at the same
endpoint with a credential this package mints:

    from objectio import Client

    admin = Client(endpoint="https://s3.example.com",
                   access_key="AKIA…", secret_key="…")

    access = admin.provision_bucket("bucket-1", provisioner_user_id=uid)

    import boto3
    s3 = boto3.client("s3", **access.boto3_kwargs("https://s3.example.com"))
    s3.put_object(Bucket=access.bucket, Key="hello.txt", Body=b"hi")

Requests are signed with SigV4 using the standard library alone, so this
package has no dependencies.
"""

from .client import Client, provisioner_user_id_from_env
from .errors import APIError, ObjectIOError
from .models import (
    AccessKey,
    Bucket,
    BucketAccess,
    ConfigEntry,
    Credentials,
    Group,
    KMSKey,
    OIDCProvider,
    Policy,
    PublicAccessBlock,
    Role,
    Tenant,
    User,
    Warehouse,
    tenant_oidc_provider_name,
)

__all__ = [
    "AccessKey",
    "APIError",
    "Bucket",
    "BucketAccess",
    "Client",
    "ConfigEntry",
    "Credentials",
    "Group",
    "KMSKey",
    "OIDCProvider",
    "ObjectIOError",
    "Policy",
    "PublicAccessBlock",
    "Role",
    "Tenant",
    "User",
    "Warehouse",
    "provisioner_user_id_from_env",
    "tenant_oidc_provider_name",
]
__version__ = "0.1.0"
