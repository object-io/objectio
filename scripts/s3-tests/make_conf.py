"""Write s3tests.conf for the users setup_users.py created.

    make_conf.py <users.json> <host> <port> <s3tests.conf>
"""

import json
import sys

users_path, host, port, out_path = sys.argv[1:5]
users = json.load(open(users_path))


def section(name, user, extra=""):
    return f"""[{name}]
display_name = {user['display_name']}
user_id = {user['user_id']}
email = {user['email']}
access_key = {user['ak']}
secret_key = {user['sk']}
{extra}
"""


conf = f"""[DEFAULT]
host = {host}
port = {port}
is_secure = False
ssl_verify = False

[fixtures]
bucket prefix = s3t-{{random}}-
iam name prefix = s3-tests-
iam path prefix = /s3-tests/

"""
# lc_debug_interval matches the aio's --lifecycle-day-secs in run.sh: a
# lifecycle "day" lasts that many seconds.
conf += section(
    "s3 main",
    users["main"],
    "api_name = us-east-1\nkms_keyid = testkey-1\nkms_keyid2 = testkey-2\n"
    "lc_debug_interval = 10\n",
)
conf += section("s3 alt", users["alt"])
conf += section("s3 tenant", users["tenant"], "tenant = testx\n")
conf += section("iam", users["iam"])
# An IAM account is a tenant, its id the tenant's name, and its root (a
# tenant admin) is known by that id too (GetCallerIdentity's UserId).
for name, key in [("iam root", "iamroot"), ("iam alt root", "iamaltroot")]:
    root = dict(users[key], user_id=users[key]["tenant"])
    conf += section(name, root, f"account_id = {root['tenant']}\n")
with open(out_path, "w") as f:
    f.write(conf)
print(f"config written to {out_path}")
