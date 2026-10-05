//! Managed policies (named, attached by ARN) and inline policies
//! (embedded in one user, group or role).
//!
//! A managed policy's ARN says whose it is: `arn:aws:iam::<tenant>:policy/…`
//! the tenant's own; `arn:aws:iam:::policy/…` a system one (a tenant sees
//! and attaches only those the operator shares); `arn:aws:iam::aws:policy/…`
//! an AWS managed one (`objectio_auth::managed`). A policy has one version,
//! `v1`.

use axum::response::Response;
use objectio_auth::managed;
use objectio_proto::metadata::{
    AttachPolicyRequest, CreatePolicyRequest, DeleteInlinePolicyRequest, DeletePolicyRequest,
    DetachPolicyRequest, GetInlinePolicyRequest, GroupMeta, ListAttachedPoliciesRequest,
    ListInlinePoliciesRequest, ListPoliciesRequest, PolicyObject, PutInlinePolicyRequest,
    RoleObject, UserMeta,
};

use super::groups::group_resource;
use super::users::path_prefix;
use super::{
    Actor, Call, IAM_NS, IamError, IamResult, Xml, aws_account, check_name, derived_id, entity_arn,
    find_group, find_role, find_user, iso, page, page_end, path_param, role_key, sort_key,
    user_resources,
};
use crate::iam_admin::{get_policy as stored_policy, key, system_policy_usable};

fn malformed(message: impl Into<String>) -> IamError {
    IamError::malformed_policy(message)
}

/// Check an identity policy (inline or managed) as IAM does: a JSON
/// object, version 2012-10-17 (or 2008-10-17), statements with an effect,
/// actions and resources, unique ids, and no principal; at most `max`
/// characters, whitespace aside.
pub(super) fn check_identity_policy(doc: &str, max: usize) -> IamResult<()> {
    let size = doc.chars().filter(|c| !c.is_whitespace()).count();
    if size > max {
        return Err(IamError::new(
            axum::http::StatusCode::CONFLICT,
            "LimitExceeded",
            format!("Maximum policy size of {max} bytes exceeded."),
        ));
    }
    let v: serde_json::Value = serde_json::from_str(doc)
        .map_err(|e| malformed(format!("Syntax errors in policy: {e}")))?;
    let Some(obj) = v.as_object() else {
        return Err(malformed("The policy must be a JSON object."));
    };
    if let Some(version) = obj.get("Version")
        && !matches!(version.as_str(), Some("2012-10-17" | "2008-10-17"))
    {
        return Err(malformed("The policy must contain a valid version string."));
    }
    let statements: Vec<&serde_json::Value> = match obj.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.iter().collect(),
        Some(one @ serde_json::Value::Object(_)) => vec![one],
        _ => return Err(malformed("Missing required field Statement.")),
    };
    if statements.is_empty() {
        return Err(malformed("Missing required field Statement."));
    }
    let mut sids = std::collections::HashSet::new();
    for st in statements {
        let Some(st) = st.as_object() else {
            return Err(malformed("Each statement must be a JSON object."));
        };
        if st.contains_key("Principal") || st.contains_key("NotPrincipal") {
            return Err(malformed("Policy document should not specify a principal."));
        }
        for unsupported in ["NotAction", "NotResource"] {
            if st.contains_key(unsupported) {
                return Err(malformed(format!("{unsupported} is not supported.")));
            }
        }
        if !matches!(
            st.get("Effect").and_then(serde_json::Value::as_str),
            Some("Allow" | "Deny")
        ) {
            return Err(malformed("Each statement must have Effect Allow or Deny."));
        }
        if !st.contains_key("Action") {
            return Err(malformed("Missing required field Action."));
        }
        if !st.contains_key("Resource") {
            return Err(malformed("Missing required field Resource."));
        }
        if let Some(sid) = st.get("Sid").and_then(serde_json::Value::as_str)
            && !sids.insert(sid.to_string())
        {
            return Err(malformed("Statement IDs (SID) in a policy must be unique."));
        }
    }
    objectio_auth::BucketPolicy::from_json(doc).map_err(|e| malformed(e.to_string()))?;
    Ok(())
}

// ── Managed policies ────────────────────────────────────────────────────

/// A managed policy an ARN names.
enum Managed {
    Aws(&'static str, &'static str),
    Stored(PolicyObject),
}

impl Managed {
    fn name(&self) -> &str {
        match self {
            Self::Aws(n, _) => n,
            Self::Stored(p) => &p.name,
        }
    }
    fn document(&self) -> &str {
        match self {
            Self::Aws(_, d) => d,
            Self::Stored(p) => &p.policy_json,
        }
    }
    fn path(&self) -> &str {
        match self {
            Self::Aws(..) => "/",
            Self::Stored(p) if p.path.is_empty() => "/",
            Self::Stored(p) => &p.path,
        }
    }
    /// How an attachment names it.
    fn stored_name(&self) -> String {
        match self {
            Self::Aws(n, _) => format!("{}{n}", managed::PREFIX),
            Self::Stored(p) => key(&p.tenant, &p.name),
        }
    }
    fn arn(&self) -> String {
        match self {
            Self::Aws(n, _) => format!("arn:aws:iam::aws:policy/{n}"),
            Self::Stored(p) => stored_arn(p),
        }
    }
    /// The canonical ARN, to authorize against.
    fn resource(&self) -> String {
        objectio_auth::policy::canonical_arn(&self.arn()).into_owned()
    }
    fn id(&self) -> String {
        match self {
            Self::Stored(p) if !p.policy_id.is_empty() => p.policy_id.clone(),
            Self::Stored(p) => derived_id("ANPA", &stored_arn(p), p.created_at),
            Self::Aws(..) => derived_id("ANPA", &self.arn(), 0),
        }
    }
    fn dates(&self) -> (u64, u64) {
        match self {
            Self::Aws(..) => (0, 0),
            Self::Stored(p) => (p.created_at, p.updated_at),
        }
    }
}

fn stored_arn(p: &PolicyObject) -> String {
    let path = if p.path.is_empty() { "/" } else { &p.path };
    format!(
        "arn:aws:iam::{}:policy{path}{}",
        aws_account(&p.tenant),
        p.name
    )
}

/// `(account, path, name)` of a policy ARN.
fn parse_policy_arn(arn: &str) -> Option<(String, String, String)> {
    let rest = arn
        .strip_prefix("arn:aws:iam::")
        .or_else(|| arn.strip_prefix("arn:obio:iam::"))?;
    let (account, resource) = rest.split_once(':')?;
    let resource = resource.strip_prefix("policy")?;
    let (path, name) = resource.rsplit_once('/')?;
    if !resource.starts_with('/') || name.is_empty() {
        return None;
    }
    Some((account.to_string(), format!("{path}/"), name.to_string()))
}

/// The managed policy `arn` names, as the actor may see it.
async fn resolve(call: &Call<'_>, actor: &Actor, arn: &str) -> IamResult<Managed> {
    let missing =
        || IamError::no_such_entity(format!("Policy {arn} does not exist or is not attachable."));
    let (account, path, name) = parse_policy_arn(arn).ok_or_else(|| {
        IamError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "InvalidInput",
            format!("ARN {arn} is not valid."),
        )
    })?;
    if account == "aws" {
        return managed::POLICIES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(n, d)| Managed::Aws(n, d))
            .filter(|_| path == "/")
            .ok_or_else(missing);
    }
    let system = account.is_empty() || account == objectio_auth::policy::SYSTEM_ACCOUNT;
    let policy = if !system && account == actor.tenant {
        stored_policy(call.app, &key(&actor.tenant, &name)).await
    } else if system {
        stored_policy(call.app, &name)
            .await
            .filter(|p| actor.tenant.is_empty() || system_policy_usable(p, false))
    } else {
        None
    };
    let policy = policy.ok_or_else(missing)?;
    let stored_path = if policy.path.is_empty() {
        "/"
    } else {
        &policy.path
    };
    if stored_path != path {
        return Err(missing());
    }
    Ok(Managed::Stored(policy))
}

fn policy_xml(x: &mut Xml, m: &Managed) {
    let (created, updated) = m.dates();
    x.el("PolicyName", m.name())
        .el("PolicyId", m.id())
        .el("Arn", m.arn())
        .el("Path", m.path())
        .el("DefaultVersionId", "v1")
        .el("IsAttachable", "true");
    if let Managed::Stored(p) = m
        && !p.description.is_empty()
    {
        x.el("Description", &p.description);
    }
    x.el("CreateDate", iso(created))
        .el("UpdateDate", iso(updated));
}

pub(super) async fn create_policy(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let name = call.required("PolicyName")?;
    check_name("PolicyName", name, 128)?;
    let path = path_param(call, "Path")?;
    let doc = call.required("PolicyDocument")?;
    check_identity_policy(doc, 6144)?;
    let description = call.param("Description");
    if description.len() > 1000 {
        return Err(IamError::validation(
            "Description is at most 1000 characters",
        ));
    }
    actor
        .allow(
            call,
            "CreatePolicy",
            &entity_arn(&actor.tenant, "policy", &path, name),
        )
        .await?;
    let policy = call
        .app
        .meta_client
        .clone()
        .create_policy(CreatePolicyRequest {
            name: name.to_string(),
            policy_json: doc.to_string(),
            tenant: actor.tenant.clone(),
            shared: false,
            path,
            description: description.to_string(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policy
        .unwrap_or_default();
    let mut x = Xml::new();
    x.open("Policy");
    policy_xml(&mut x, &Managed::Stored(policy));
    x.close("Policy");
    call.ok(Some(x), IAM_NS)
}

async fn get_policy_call(call: &Call<'_>, actor: &Actor) -> IamResult<Managed> {
    let m = resolve(call, actor, call.required("PolicyArn")?).await?;
    actor.allow(call, call.action, &m.resource()).await?;
    Ok(m)
}

pub(super) async fn get_policy(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let m = get_policy_call(call, actor).await?;
    let mut x = Xml::new();
    x.open("Policy");
    policy_xml(&mut x, &m);
    x.close("Policy");
    call.ok(Some(x), IAM_NS)
}

fn version_xml(x: &mut Xml, m: &Managed, with_document: bool) {
    if with_document {
        x.document("Document", m.document());
    }
    x.el("VersionId", "v1")
        .el("IsDefaultVersion", "true")
        .el("CreateDate", iso(m.dates().0));
}

pub(super) async fn get_policy_version(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let m = get_policy_call(call, actor).await?;
    if call.required("VersionId")? != "v1" {
        return Err(IamError::no_such_entity(format!(
            "Policy {} version {} does not exist.",
            m.arn(),
            call.param("VersionId")
        )));
    }
    let mut x = Xml::new();
    x.open("PolicyVersion");
    version_xml(&mut x, &m, true);
    x.close("PolicyVersion");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_policy_versions(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let m = get_policy_call(call, actor).await?;
    let mut x = Xml::new();
    x.open("Versions").open("member");
    version_xml(&mut x, &m, false);
    x.close("member").close("Versions");
    page_end(&mut x, None);
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_policies(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let scope = call.opt("Scope").filter(|s| !s.is_empty()).unwrap_or("All");
    if !matches!(scope, "All" | "AWS" | "Local") {
        return Err(IamError::validation("Scope must be All, AWS or Local"));
    }
    let prefix = path_prefix(call);
    actor
        .allow(
            call,
            "ListPolicies",
            &entity_arn(&actor.tenant, "policy", "/", "*"),
        )
        .await?;
    let mut all: Vec<Managed> = Vec::new();
    if scope != "AWS" {
        let stored = call
            .app
            .meta_client
            .clone()
            .list_policies(ListPoliciesRequest {})
            .await
            .map_err(|e| IamError::from_status(&e))?
            .into_inner()
            .policies;
        all.extend(
            stored
                .into_iter()
                .filter(|p| {
                    p.tenant == actor.tenant
                        || (scope == "All"
                            && !actor.tenant.is_empty()
                            && system_policy_usable(p, false))
                })
                .map(Managed::Stored),
        );
    }
    if scope != "Local" {
        all.extend(managed::POLICIES.iter().map(|(n, d)| Managed::Aws(n, d)));
    }
    let items = all
        .into_iter()
        .filter(|m| m.path().starts_with(&prefix))
        .map(|m| (m.arn(), m))
        .collect();
    let (items, next) = page(call, items)?;
    let mut x = Xml::new();
    x.open("Policies");
    for m in &items {
        x.open("member");
        policy_xml(&mut x, m);
        x.close("member");
    }
    x.close("Policies");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn delete_policy(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let m = get_policy_call(call, actor).await?;
    let Managed::Stored(p) = &m else {
        return Err(IamError::access_denied(
            "AWS managed policies can't be deleted",
        ));
    };
    // A tenant sees the shared system policies; it can't change them.
    if p.tenant != actor.tenant {
        return Err(IamError::access_denied(
            "a system policy is the operator's to delete",
        ));
    }
    call.app
        .meta_client
        .clone()
        .delete_policy(DeletePolicyRequest {
            name: key(&p.tenant, &p.name),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.app.policy_cache.invalidate_all_identities();
    call.ok(None, IAM_NS)
}

// ── Whose policies ──────────────────────────────────────────────────────

/// The user, group or role a policy call names.
enum Target {
    User(UserMeta),
    Group(GroupMeta),
    Role(RoleObject),
}

impl Target {
    /// From the action's noun and its `UserName`, `GroupName` or `RoleName`.
    async fn of(call: &Call<'_>, actor: &Actor) -> IamResult<Self> {
        let a = call.action;
        if a.contains("User") {
            Ok(Self::User(
                find_user(call, actor, call.required("UserName")?).await?,
            ))
        } else if a.contains("Group") {
            Ok(Self::Group(
                find_group(call, actor, call.required("GroupName")?).await?,
            ))
        } else {
            Ok(Self::Role(
                find_role(call, actor, call.required("RoleName")?).await?,
            ))
        }
    }

    /// How meta names its attachments and inline policies.
    fn principal(&self) -> String {
        match self {
            Self::User(u) => format!("user:{}", u.user_id),
            Self::Group(g) => format!("group:{}", g.group_id),
            Self::Role(r) => format!("role:{}", role_key(r)),
        }
    }

    /// The key the authorization chain caches its policies under.
    fn cache_key(&self) -> String {
        match self {
            Self::User(u) => u.user_id.clone(),
            Self::Group(g) => g.group_id.clone(),
            Self::Role(r) => format!("role:{}", role_key(r)),
        }
    }

    fn resources(&self) -> Vec<String> {
        match self {
            Self::User(u) => user_resources(u),
            Self::Group(g) => vec![group_resource(g)],
            Self::Role(r) => vec![objectio_auth::policy::canonical_arn(&r.arn).into_owned()],
        }
    }

    /// `(element, name)` naming it in a response.
    fn named(&self) -> (&'static str, &str) {
        match self {
            Self::User(u) => ("UserName", &u.display_name),
            Self::Group(g) => ("GroupName", &g.group_name),
            Self::Role(r) => ("RoleName", &r.name),
        }
    }

    fn attachments(&self, policy_name: String) -> (String, String, String, String) {
        match self {
            Self::User(u) => (policy_name, u.user_id.clone(), String::new(), String::new()),
            Self::Group(g) => (
                policy_name,
                String::new(),
                g.group_id.clone(),
                String::new(),
            ),
            Self::Role(r) => (policy_name, String::new(), String::new(), role_key(r)),
        }
    }

    /// The most an inline policy of it may hold, as IAM limits them.
    const fn inline_limit(&self) -> usize {
        match self {
            Self::User(_) => 2048,
            Self::Group(_) => 5120,
            Self::Role(_) => 10240,
        }
    }
}

pub(super) async fn attach(call: &Call<'_>, actor: &Actor, attach: bool) -> IamResult<Response> {
    let target = Target::of(call, actor).await?;
    actor
        .allow_any(call, call.action, &target.resources())
        .await?;
    let arn = call.required("PolicyArn")?;
    let stored = if attach {
        resolve(call, actor, arn).await?.stored_name()
    } else {
        // Detach what is attached, whether or not the policy still is.
        match resolve(call, actor, arn).await {
            Ok(m) => m.stored_name(),
            Err(_) => {
                return Err(IamError::no_such_entity(format!(
                    "Policy {arn} was not found."
                )));
            }
        }
    };
    let (policy_name, user_id, group_id, role_name) = target.attachments(stored);
    let mut meta = call.app.meta_client.clone();
    if attach {
        meta.attach_policy(AttachPolicyRequest {
            policy_name,
            user_id,
            group_id,
            role_name,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    } else {
        let detached = meta
            .detach_policy(DetachPolicyRequest {
                policy_name,
                user_id,
                group_id,
                role_name,
            })
            .await
            .map_err(|e| IamError::from_status(&e))?
            .into_inner()
            .success;
        if !detached {
            return Err(IamError::no_such_entity(format!(
                "Policy {arn} was not found."
            )));
        }
    }
    call.app
        .policy_cache
        .invalidate_identity(&target.cache_key());
    call.ok(None, IAM_NS)
}

/// `(name, ARN)` of an attachment's stored policy name.
async fn attached_as(call: &Call<'_>, stored: &str) -> Option<(String, String)> {
    if let Some(name) = stored.strip_prefix(managed::PREFIX) {
        return Some((name.to_string(), format!("arn:aws:iam::aws:policy/{name}")));
    }
    let p = stored_policy(call.app, stored).await?;
    Some((p.name.clone(), stored_arn(&p)))
}

pub(super) async fn list_attached(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let target = Target::of(call, actor).await?;
    actor
        .allow_any(call, call.action, &target.resources())
        .await?;
    let (_, user_id, group_id, role_name) = target.attachments(String::new());
    let names = call
        .app
        .meta_client
        .clone()
        .list_attached_policies(ListAttachedPoliciesRequest {
            user_id,
            group_id,
            role_name,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policy_names;
    let prefix = path_prefix(call);
    let mut items = Vec::new();
    for stored in names {
        if let Some((name, arn)) = attached_as(call, &stored).await {
            let path_ok = arn
                .rsplit_once('/')
                .and_then(|(head, _)| head.split_once(":policy"))
                .is_some_and(|(_, path)| format!("{path}/").starts_with(&prefix));
            if path_ok {
                items.push((sort_key(&name), (name, arn)));
            }
        }
    }
    let (items, next) = page(call, items)?;
    let mut x = Xml::new();
    x.open("AttachedPolicies");
    for (name, arn) in &items {
        x.open("member")
            .el("PolicyName", name)
            .el("PolicyArn", arn)
            .close("member");
    }
    x.close("AttachedPolicies");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

// ── Inline policies ─────────────────────────────────────────────────────

pub(super) async fn put_inline(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let name = call.required("PolicyName")?;
    check_name("PolicyName", name, 128)?;
    let target = Target::of(call, actor).await?;
    let doc = call.required("PolicyDocument")?;
    check_identity_policy(doc, target.inline_limit())?;
    actor
        .allow_any(call, call.action, &target.resources())
        .await?;
    call.app
        .meta_client
        .clone()
        .put_inline_policy(PutInlinePolicyRequest {
            principal: target.principal(),
            name: name.to_string(),
            policy_json: doc.to_string(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.app
        .policy_cache
        .invalidate_identity(&target.cache_key());
    call.ok(None, IAM_NS)
}

pub(super) async fn get_inline(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let target = Target::of(call, actor).await?;
    let name = call.required("PolicyName")?;
    actor
        .allow_any(call, call.action, &target.resources())
        .await?;
    let r = call
        .app
        .meta_client
        .clone()
        .get_inline_policy(GetInlinePolicyRequest {
            principal: target.principal(),
            name: name.to_string(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner();
    let policy = r.policy.filter(|_| r.found).ok_or_else(|| {
        IamError::no_such_entity(format!("The policy with name {name} cannot be found."))
    })?;
    let (element, owner) = target.named();
    let mut x = Xml::new();
    x.el(element, owner)
        .el("PolicyName", &policy.name)
        .document("PolicyDocument", &policy.policy_json);
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_inline(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let target = Target::of(call, actor).await?;
    actor
        .allow_any(call, call.action, &target.resources())
        .await?;
    let items = call
        .app
        .meta_client
        .clone()
        .list_inline_policies(ListInlinePoliciesRequest {
            principal: target.principal(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policies
        .into_iter()
        .map(|p| (p.name.clone(), p.name))
        .collect();
    let (names, next) = page(call, items)?;
    let mut x = Xml::new();
    x.open("PolicyNames");
    for n in &names {
        x.el("member", n);
    }
    x.close("PolicyNames");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn delete_inline(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let target = Target::of(call, actor).await?;
    let name = call.required("PolicyName")?;
    actor
        .allow_any(call, call.action, &target.resources())
        .await?;
    call.app
        .meta_client
        .clone()
        .delete_inline_policy(DeleteInlinePolicyRequest {
            principal: target.principal(),
            name: name.to_string(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.app
        .policy_cache
        .invalidate_identity(&target.cache_key());
    call.ok(None, IAM_NS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_arns_name_an_account_a_path_and_a_name() {
        assert_eq!(
            parse_policy_arn("arn:aws:iam::acme:policy/team/read"),
            Some(("acme".into(), "/team/".into(), "read".into()))
        );
        assert_eq!(
            parse_policy_arn("arn:aws:iam::aws:policy/AmazonS3FullAccess"),
            Some(("aws".into(), "/".into(), "AmazonS3FullAccess".into()))
        );
        assert_eq!(
            parse_policy_arn("arn:aws:iam:::policy/readonly"),
            Some((String::new(), "/".into(), "readonly".into()))
        );
        assert_eq!(parse_policy_arn("arn:aws:iam::acme:user/x"), None);
        assert_eq!(parse_policy_arn("arn:aws:iam::acme:policy/"), None);
    }

    #[test]
    fn identity_policies_are_checked_as_iam_checks_them() {
        let ok = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
        assert!(check_identity_policy(ok, 2048).is_ok());
        for bad in [
            r#"{"Version":"2010-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            r#"{"Version":"2012-10-17"}"#,
            r#"{"Version":"2012-10-17","Statement":[
                {"Sid":"a","Effect":"Allow","Action":"*","Resource":"*"},
                {"Sid":"a","Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*",
                "Resource":"*","Principal":"arn:aws:iam:::username"}]}"#,
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}]}"#,
            "not json",
        ] {
            let e = check_identity_policy(bad, 2048).unwrap_err();
            assert_eq!(e.status, axum::http::StatusCode::BAD_REQUEST, "{bad}");
        }
        let big = format!(
            r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
            vec![r#"{"Effect":"Allow","Action":"*","Resource":"*"}"#; 100].join(",")
        );
        assert_eq!(
            check_identity_policy(&big, 2048).unwrap_err().code,
            "LimitExceeded"
        );
    }
}
