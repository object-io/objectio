"""Create the users and settings ceph's s3-tests expect, through the admin API.

    setup_users.py <endpoint> <admin-creds.env> <users.json>

The system admin bypasses bucket policies, so it is never one of the test
users: s3-tests' "main", "alt" and "tenant" users are ordinary users with
their own keys. Prints what it did; writes the users' ids and keys to
<users.json> for make_conf.py.
"""

import json
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
)

from objectio import Client  # noqa: E402
from objectio.models import PublicAccessBlock  # noqa: E402

endpoint, creds_path, out_path = sys.argv[1:4]
env = dict(
    line.replace("export ", "").strip().split("=", 1)
    for line in open(creds_path)
    if line.startswith("export")
)
client = Client(
    endpoint=endpoint,
    access_key=env["AWS_ACCESS_KEY_ID"],
    secret_key=env["AWS_SECRET_ACCESS_KEY"],
)

for tenant in ["s3t", "testx", "iamr", "iamalt"]:
    try:
        client.create_tenant(tenant)
    except Exception as e:  # already there on a reused cluster
        print("tenant", tenant, e)

users = {}


def make(name, tenant, email):
    user = client.create_user(name, tenant=tenant)
    try:
        user = client.update_user(user.user_id, email=email)
    except Exception as e:
        print("email", name, e)
    key = client.create_access_key(user.user_id)
    users[name] = {
        "user_id": user.user_id,
        "display_name": user.display_name,
        "email": email,
        "ak": key.access_key_id,
        "sk": key.secret_access_key,
        "tenant": tenant,
    }


make("main", "s3t", "main@example.com")
make("alt", "s3t", "alt@example.com")
make("tenant", "testx", "tenant@example.com")
make("iam", "s3t", "iam@example.com")
make("iamroot", "iamr", "iamroot@example.com")
make("iamaltroot", "iamalt", "iamaltroot@example.com")

# The IAM API's tests. "iam" manages other users' policies and roles in
# s3t, as an ordinary user its policy lets do so (RGW gives it caps). The
# two "root" users are their tenants' admins: the IAM API's account root.
client.attach_policy("aws:IAMFullAccess", user_id=users["iam"]["user_id"])
client.add_tenant_admin("iamr", users["iamroot"]["user_id"])
client.add_tenant_admin("iamalt", users["iamaltroot"]["user_id"])

# s3-tests makes buckets public with policies; the cluster default blocks
# public access on new buckets.
try:
    print(
        client.put_public_access_block(
            PublicAccessBlock(False, False, False, False), new_buckets_blocked=False
        )
    )
except Exception as e:
    print("public access block", e)

# The SSE-KMS tests name these key ids.
for key_id in ["testkey-1", "testkey-2"]:
    try:
        print(client.create_kms_key(key_id, "s3-tests"))
    except Exception as e:
        print("kms", key_id, e)

with open(out_path, "w") as f:
    json.dump(users, f, indent=1)
print(f"users written to {out_path}")
