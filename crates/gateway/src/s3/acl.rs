//! ACLs (refused: buckets are BucketOwnerEnforced) and ownership controls.

use super::*;

/// The refusal S3 gives an ACL a bucket owner enforced bucket won't take.
pub(crate) fn acls_not_supported() -> Response {
    S3Error::xml_response(
        "AccessControlListNotSupported",
        "The bucket does not allow ACLs",
        StatusCode::BAD_REQUEST,
    )
}

/// A write's `x-amz-acl` / `x-amz-grant-*` headers asking for more than
/// the owner's FULL_CONTROL.
pub(crate) fn acl_header_refusal(headers: &HeaderMap) -> Option<Response> {
    let canned_ok = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v == "private" || v == "bucket-owner-full-control");
    let grants = headers
        .keys()
        .any(|k| k.as_str().starts_with("x-amz-grant-"));
    (!canned_ok || grants).then(acls_not_supported)
}

/// The owner of `bucket` (who owns everything in it), or the response.
pub(crate) async fn bucket_owner(state: &AppState, bucket: &str) -> Result<String, Response> {
    match state
        .meta_client
        .clone()
        .get_bucket(GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
    {
        Ok(r) => Ok(r.into_inner().bucket.map(|b| b.owner).unwrap_or_default()),
        Err(e) if e.code() == tonic::Code::NotFound => Err(S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(e) => Err(S3Error::from_status(&e)),
    }
}

/// GetBucketAcl / GetObjectAcl: the owner, with FULL_CONTROL.
pub(crate) async fn get_acl(
    state: &AppState,
    bucket: &str,
    key: Option<&str>,
    version_id: Option<&str>,
) -> Response {
    let owner = match bucket_owner(state, bucket).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if let Some(key) = key {
        let nodes = match get_placement_nodes_for_object(state, bucket, key).await {
            Ok(n) => n,
            Err(resp) => return resp,
        };
        if let Err(resp) = object_to_read(state, &nodes, bucket, key, version_id, false).await {
            return resp;
        }
    }
    let id = quick_xml::escape::escape(&owner);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>{id}</ID><DisplayName>{id}</DisplayName></Owner>\
         <AccessControlList><Grant>\
         <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
         <ID>{id}</ID><DisplayName>{id}</DisplayName></Grantee>\
         <Permission>FULL_CONTROL</Permission></Grant></AccessControlList>\
         </AccessControlPolicy>"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// PutBucketAcl / PutObjectAcl: accepted only if it grants the owner
/// FULL_CONTROL and no one anything. It changes nothing either way. A
/// PutObjectAcl used to be taken as a PutObject: the ACL document became
/// the object's data.
pub(crate) async fn put_acl(
    state: &AppState,
    bucket: &str,
    key: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let owner = match bucket_owner(state, bucket).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if let Some(key) = key {
        let nodes = match get_placement_nodes_for_object(state, bucket, key).await {
            Ok(n) => n,
            Err(resp) => return resp,
        };
        let version = headers
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok());
        if let Err(resp) = object_to_read(state, &nodes, bucket, key, version, false).await {
            return resp;
        }
    }
    if let Some(refused) = acl_header_refusal(headers) {
        return refused;
    }
    if !body.is_empty() && !acl_body_is_owner_only(body, &owner) {
        return acls_not_supported();
    }
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

/// Whether an `AccessControlPolicy` body grants FULL_CONTROL to `owner`
/// and nothing to anyone else.
pub(crate) fn acl_body_is_owner_only(body: &[u8], owner: &str) -> bool {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut grants = 0;
    let mut grant_id: Option<String> = None;
    let mut grant_other = false;
    let mut permission = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                path.push(String::from_utf8_lossy(e.local_name().as_ref()).into_owned());
                if path.last().is_some_and(|n| n == "Grant") {
                    grant_id = None;
                    grant_other = false;
                    permission.clear();
                }
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .unescape()
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default();
                let n = path.len();
                if n >= 2 && path[n - 2] == "Grantee" {
                    match path[n - 1].as_str() {
                        "ID" => grant_id = Some(text),
                        "URI" | "EmailAddress" => grant_other = true,
                        _ => {}
                    }
                } else if path.last().is_some_and(|p| p == "Permission") {
                    permission = text;
                }
            }
            Ok(Event::End(_)) => {
                if path.pop().is_some_and(|n| n == "Grant") {
                    grants += 1;
                    if grant_other
                        || grant_id.as_deref() != Some(owner)
                        || permission != "FULL_CONTROL"
                    {
                        return false;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return false,
            _ => {}
        }
        buf.clear();
    }
    grants > 0
}

/// GetBucketOwnershipControls: always bucket owner enforced.
pub(crate) async fn get_ownership_controls(state: &AppState, bucket: &str) -> Response {
    if let Err(resp) = bucket_owner(state, bucket).await {
        return resp;
    }
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
               <OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
               <Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule>\
               </OwnershipControls>";
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// PutBucketOwnershipControls: only BucketOwnerEnforced, which is how it is.
pub(crate) async fn put_ownership_controls(
    state: &AppState,
    bucket: &str,
    body: &[u8],
) -> Response {
    if let Err(resp) = bucket_owner(state, bucket).await {
        return resp;
    }
    if String::from_utf8_lossy(body)
        .contains("<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>")
    {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap()
    } else {
        S3Error::xml_response(
            "InvalidRequest",
            "Only BucketOwnerEnforced object ownership is supported: ACLs are disabled",
            StatusCode::BAD_REQUEST,
        )
    }
}
