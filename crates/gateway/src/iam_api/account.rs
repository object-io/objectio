//! The account as a whole: its summary, and the identity providers it
//! trusts.

use axum::response::Response;
use objectio_proto::metadata::{GetTenantRequest, ListConfigRequest, ListPoliciesRequest};

use super::{
    Actor, Call, IAM_NS, IamError, IamResult, Xml, all_groups, all_users, aws_account, tenant_roles,
};

/// AWS's default IAM quotas, which `GetAccountSummary` reports for the
/// clients that read them. ObjectIO enforces none of them.
const QUOTAS: &[(&str, u64)] = &[
    ("UsersQuota", 5000),
    ("GroupsQuota", 300),
    ("RolesQuota", 1000),
    ("PoliciesQuota", 1500),
    ("AccessKeysPerUserQuota", 2),
    ("GroupsPerUserQuota", 10),
    ("AttachedPoliciesPerUserQuota", 10),
    ("AttachedPoliciesPerGroupQuota", 10),
    ("AttachedPoliciesPerRoleQuota", 10),
    ("PolicySizeQuota", 6144),
    ("UserPolicySizeQuota", 2048),
    ("GroupPolicySizeQuota", 5120),
];

pub(super) async fn get_account_summary(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    actor.allow(call, "GetAccountSummary", "*").await?;
    let users = all_users(call.app)
        .await?
        .into_iter()
        .filter(|u| u.tenant == actor.tenant)
        .count();
    let groups = all_groups(call.app)
        .await?
        .into_iter()
        .filter(|g| g.tenant == actor.tenant)
        .count();
    let roles = tenant_roles(call.app, &actor.tenant).await?.len();
    let policies = call
        .app
        .meta_client
        .clone()
        .list_policies(ListPoliciesRequest {})
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policies
        .into_iter()
        .filter(|p| p.tenant == actor.tenant)
        .count();
    let mut x = Xml::new();
    x.open("SummaryMap");
    let counts = [
        ("Users", users),
        ("Groups", groups),
        ("Roles", roles),
        ("Policies", policies),
    ];
    for (k, v) in counts
        .iter()
        .map(|(k, v)| (*k, *v as u64))
        .chain(QUOTAS.iter().copied())
    {
        x.open("entry")
            .el("key", k)
            .el("value", v.to_string())
            .close("entry");
    }
    x.close("SummaryMap");
    call.ok(Some(x), IAM_NS)
}

/// The OpenID Connect providers the account trusts, as configured
/// (`identity/openid/<name>`): a tenant's own (`t-<tenant>`) and the one
/// bound to it; for the system, those marked `system_admin`. Read-only:
/// providers are configured through the admin API.
pub(super) async fn list_open_id_connect_providers(
    call: &Call<'_>,
    actor: &Actor,
) -> IamResult<Response> {
    actor.allow(call, "ListOpenIDConnectProviders", "*").await?;
    let mut meta = call.app.meta_client.clone();
    let entries = meta
        .list_config(ListConfigRequest {
            prefix: "identity/openid/".to_string(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .entries;
    let bound = if actor.tenant.is_empty() {
        String::new()
    } else {
        meta.get_tenant(GetTenantRequest {
            name: actor.tenant.clone(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().tenant)
        .map(|t| t.oidc_provider)
        .unwrap_or_default()
    };
    let own = format!("t-{}", actor.tenant.to_lowercase());
    let mut arns: Vec<String> = entries
        .into_iter()
        .filter_map(|e| {
            let name = e.key.strip_prefix("identity/openid/")?.to_string();
            let config: serde_json::Value = serde_json::from_slice(&e.value).ok()?;
            let mine = if actor.tenant.is_empty() {
                config
                    .get("system_admin")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            } else {
                name == own || (!bound.is_empty() && name == bound)
            };
            let issuer = config.get("issuer_url")?.as_str()?;
            let host = issuer
                .strip_prefix("https://")
                .or_else(|| issuer.strip_prefix("http://"))
                .unwrap_or(issuer)
                .trim_end_matches('/');
            mine.then(|| {
                format!(
                    "arn:aws:iam::{}:oidc-provider/{host}",
                    aws_account(&actor.tenant)
                )
            })
        })
        .collect();
    arns.sort();
    arns.dedup();
    let mut x = Xml::new();
    x.open("OpenIDConnectProviderList");
    for arn in &arns {
        x.open("member").el("Arn", arn).close("member");
    }
    x.close("OpenIDConnectProviderList");
    call.ok(Some(x), IAM_NS)
}
