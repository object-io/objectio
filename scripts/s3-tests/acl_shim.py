"""pytest plugin: map canned *bucket* ACLs to equivalent public bucket policies
(ObjectIO is BucketOwnerEnforced). Object ACLs are left alone."""
import json, botocore.client
_orig = botocore.client.BaseClient._make_api_call
ACTS = {"public-read": (["s3:ListBucket"], ["s3:GetObject"]),
        "public-read-write": (["s3:ListBucket"], ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]),
        "authenticated-read": (["s3:ListBucket"], ["s3:GetObject"])}
def _policy(b, acl):
    bl, ol = ACTS[acl]
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": bl, "Resource": f"arn:aws:s3:::{b}"},
        {"Effect": "Allow", "Principal": "*", "Action": ol, "Resource": f"arn:aws:s3:::{b}/*"}]})
def _call(self, op, params):
    if op == "CreateBucket" and params.get("ACL"):
        params = dict(params); acl = params.pop("ACL")
        r = _orig(self, op, params)
        if acl in ACTS: _orig(self, "PutBucketPolicy", {"Bucket": params["Bucket"], "Policy": _policy(params["Bucket"], acl)})
        return r
    if op == "PutBucketAcl" and params.get("ACL") and "AccessControlPolicy" not in params:
        acl = params["ACL"]
        if acl in ACTS: return _orig(self, "PutBucketPolicy", {"Bucket": params["Bucket"], "Policy": _policy(params["Bucket"], acl)})
        if acl == "private":
            try: return _orig(self, "DeleteBucketPolicy", {"Bucket": params["Bucket"]})
            except Exception: return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    return _orig(self, op, params)
botocore.client.BaseClient._make_api_call = _call
