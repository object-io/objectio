//! Identity providers, STS, Block Public Access and the audit stream.

use super::{Ctx, escape_path, q, read_input, read_json, seg, tenant_query};
use crate::cli::{AuditCmd, OidcCmd, PabBucketCmd, PabCmd, PabFlags, StsCmd};
use crate::http::{Body, xml_tag};
use crate::output::{cell, key_values as kv, rows_of};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::fmt::Write as _;

/// Where providers live in the stored configuration.
const OIDC_PREFIX: &str = "identity/openid/";

/// A tenant's own provider name: `t-<tenant>`, lowercased. The one a tenant
/// admin may create, and the one STS trusts for the tenant's roles.
pub fn tenant_provider_name(tenant: &str) -> String {
    format!("t-{}", tenant.to_lowercase())
}

fn provider_path(name: &str) -> String {
    format!(
        "/_admin/config/{}",
        escape_path(&format!("{OIDC_PREFIX}{name}"))
    )
}

pub async fn oidc(cmd: OidcCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        OidcCmd::List => {
            let v = ctx
                .api
                .get("/_admin/config", &q(&[("prefix", OIDC_PREFIX)]))
                .await?;
            let rows: Vec<Value> = rows_of(&v, "entries")
                .into_iter()
                .map(|e| {
                    let name = e["key"]
                        .as_str()
                        .unwrap_or_default()
                        .trim_start_matches(OIDC_PREFIX)
                        .to_string();
                    json!({
                        "name": name,
                        "issuer_url": e["value"]["issuer_url"],
                        "client_id": e["value"]["client_id"],
                        "enabled": e["value"].get("enabled").cloned().unwrap_or(json!(true)),
                        "system_admin": e["value"].get("system_admin").cloned().unwrap_or(json!(false)),
                    })
                })
                .collect();
            ctx.out.list(
                &v,
                &rows,
                &[
                    ("NAME", "name"),
                    ("ISSUER", "issuer_url"),
                    ("CLIENT ID", "client_id"),
                    ("ENABLED", "enabled"),
                    ("SYSTEM ADMIN", "system_admin"),
                ],
                "No identity providers.",
            )?;
        }
        OidcCmd::Show { name } => {
            let v = ctx.api.get(&provider_path(&name), &[]).await?;
            // The stored document, client_secret already redacted by the
            // server.
            ctx.out.emit(&v, |v| kv(&v["value"]))?;
        }
        OidcCmd::Put { name, file } => {
            let doc = read_json(&file)?;
            if !doc.is_object() {
                bail!("{} must hold a JSON object", file.display());
            }
            let v = ctx
                .api
                .call("PUT", &provider_path(&name), &[], Body::Json(doc))
                .await?
                .json()?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Stored identity provider {name} (version {})\n",
                    cell(&v["version"])
                )
            })?;
        }
        OidcCmd::Delete { name } => {
            ctx.api.delete(&provider_path(&name), &[]).await?;
            ctx.out.done(&format!("Deleted identity provider {name}"))?;
        }
        OidcCmd::TenantName { tenant } => {
            let name = tenant_provider_name(&tenant);
            ctx.out
                .emit(&json!({ "name": name }), |_| format!("{name}\n"))?;
        }
    }
    Ok(())
}

/// The form an `AssumeRoleWithWebIdentity` request posts.
pub fn sts_form(role_arn: &str, token: &str, session: &str, duration: Option<u32>) -> String {
    let mut pairs = vec![
        ("Action", "AssumeRoleWithWebIdentity".to_string()),
        ("Version", "2011-06-15".to_string()),
        ("RoleArn", role_arn.to_string()),
        ("WebIdentityToken", token.to_string()),
        ("RoleSessionName", session.to_string()),
    ];
    if let Some(d) = duration {
        pairs.push(("DurationSeconds", d.to_string()));
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", crate::sigv4::escape_rfc3986(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The credentials out of an STS answer, under the names the AWS CLI's
/// `sts assume-role-with-web-identity` uses.
pub fn sts_credentials(xml: &str) -> Result<Value> {
    let ak = xml_tag(xml, "AccessKeyId").context("the STS answer carried no credentials")?;
    Ok(json!({
        "AccessKeyId": ak,
        "SecretAccessKey": xml_tag(xml, "SecretAccessKey").unwrap_or_default(),
        "SessionToken": xml_tag(xml, "SessionToken").unwrap_or_default(),
        "Expiration": xml_tag(xml, "Expiration").unwrap_or_default(),
        "AssumedRoleArn": xml_tag(xml, "Arn").unwrap_or_default(),
    }))
}

pub async fn sts(cmd: StsCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    let StsCmd::AssumeRoleWithWebIdentity {
        role_arn,
        token,
        token_file,
        session_name,
        duration_seconds,
        env,
    } = cmd;
    let token = match (token, token_file) {
        (Some(t), _) => t,
        (None, Some(f)) => String::from_utf8(read_input(&f)?)
            .context("the token file is not UTF-8")?
            .trim()
            .to_string(),
        (None, None) => bail!("give --token or --token-file"),
    };
    let form = sts_form(&role_arn, &token, &session_name, duration_seconds);
    let reply = ctx
        .api
        .call_unsigned(
            "POST",
            "/",
            &[],
            Body::Raw {
                bytes: form.into_bytes(),
                content_type: "application/x-www-form-urlencoded".into(),
            },
        )
        .await?;
    let creds = sts_credentials(&reply.text())?;
    if env {
        ctx.out.print(&format!(
            "export AWS_ACCESS_KEY_ID={}\nexport AWS_SECRET_ACCESS_KEY={}\nexport AWS_SESSION_TOKEN={}\n",
            creds["AccessKeyId"].as_str().unwrap_or_default(),
            creds["SecretAccessKey"].as_str().unwrap_or_default(),
            creds["SessionToken"].as_str().unwrap_or_default(),
        ))?;
    } else {
        ctx.out.emit(&creds, kv)?;
    }
    Ok(())
}

/// The four flags as the API spells them. Every flag is written: a PUT
/// replaces the block.
pub fn pab_doc(f: &PabFlags) -> Value {
    json!({
        "BlockPublicAcls": f.all || f.block_public_acls,
        "IgnorePublicAcls": f.all || f.ignore_public_acls,
        "BlockPublicPolicy": f.all || f.block_public_policy,
        "RestrictPublicBuckets": f.all || f.restrict_public_buckets,
    })
}

const PAB_FLAGS: [&str; 4] = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
];

/// The S3 XML for a bucket's block.
pub fn pab_xml(doc: &Value) -> String {
    let flags = PAB_FLAGS.iter().fold(String::new(), |mut acc, k| {
        let _ = write!(acc, "<{k}>{}</{k}>", doc[k].as_bool().unwrap_or(false));
        acc
    });
    format!(
        "<PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{flags}</PublicAccessBlockConfiguration>"
    )
}

/// A bucket's block XML as the same JSON shape the admin API uses.
pub fn pab_from_xml(xml: &str) -> Value {
    let mut out = serde_json::Map::new();
    for k in PAB_FLAGS {
        out.insert(
            k.to_string(),
            json!(xml_tag(xml, k).is_some_and(|v| v.eq_ignore_ascii_case("true"))),
        );
    }
    Value::Object(out)
}

pub async fn public_access_block(cmd: PabCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        PabCmd::Get { tenant } => {
            let v = ctx
                .api
                .get("/_admin/public-access-block", &tenant_query(&tenant))
                .await?;
            ctx.out.emit(&v, |v| {
                let mut v = v.clone();
                if v["tenant"].as_str() == Some("") {
                    v["tenant"] = json!("(cluster)");
                }
                kv(&v)
            })?;
        }
        PabCmd::Put {
            flags,
            new_buckets_blocked,
            tenant,
        } => {
            let mut body = pab_doc(&flags);
            if let Some(b) = new_buckets_blocked {
                body["new_buckets_blocked"] = json!(b);
            }
            let v = ctx
                .api
                .send_json(
                    "PUT",
                    "/_admin/public-access-block",
                    &tenant_query(&tenant),
                    body,
                )
                .await?;
            ctx.out.emit(&v, kv)?;
        }
        PabCmd::Delete { tenant } => {
            ctx.api
                .delete("/_admin/public-access-block", &tenant_query(&tenant))
                .await?;
            ctx.out.done("Public access block removed")?;
        }
        PabCmd::Bucket { action } => pab_bucket(action, ctx).await?,
    }
    Ok(())
}

async fn pab_bucket(cmd: PabBucketCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        PabBucketCmd::Get { bucket } => {
            let r = ctx
                .api
                .call(
                    "GET",
                    &format!("/{}", seg(&bucket)),
                    &q(&[("publicAccessBlock", "")]),
                    Body::Empty,
                )
                .await?;
            let v = pab_from_xml(&r.text());
            ctx.out.emit(&v, kv)?;
        }
        PabBucketCmd::Put { bucket, flags } => {
            ctx.api
                .call(
                    "PUT",
                    &format!("/{}", seg(&bucket)),
                    &q(&[("publicAccessBlock", "")]),
                    Body::Raw {
                        bytes: pab_xml(&pab_doc(&flags)).into_bytes(),
                        content_type: "application/xml".into(),
                    },
                )
                .await?;
            ctx.out
                .done(&format!("Public access block set on {bucket}"))?;
        }
        PabBucketCmd::Delete { bucket } => {
            ctx.api
                .call(
                    "DELETE",
                    &format!("/{}", seg(&bucket)),
                    &q(&[("publicAccessBlock", "")]),
                    Body::Empty,
                )
                .await?;
            ctx.out
                .done(&format!("Public access block removed from {bucket}"))?;
        }
        PabBucketCmd::PolicyStatus { bucket } => {
            let r = ctx
                .api
                .call(
                    "GET",
                    &format!("/{}", seg(&bucket)),
                    &q(&[("policyStatus", "")]),
                    Body::Empty,
                )
                .await?;
            let public = xml_tag(&r.text(), "IsPublic").is_some_and(|v| v == "true");
            ctx.out.emit(&json!({ "IsPublic": public }), kv)?;
        }
    }
    Ok(())
}

pub async fn audit(cmd: AuditCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        AuditCmd::Get { tenant } => {
            let v = ctx.api.get("/_admin/audit", &tenant_query(&tenant)).await?;
            ctx.out.emit(&v, |v| {
                let mut summary = v.clone();
                let targets = summary
                    .as_object_mut()
                    .and_then(|o| o.remove("targets"))
                    .unwrap_or_else(|| json!([]));
                if summary["tenant"].as_str() == Some("") {
                    summary["tenant"] = json!("(cluster)");
                }
                let rows = rows_of(&targets, "targets");
                let t = if rows.is_empty() {
                    "No targets.\n".to_string()
                } else {
                    crate::output::table(
                        &rows,
                        &[
                            ("NAME", "name"),
                            ("TYPE", "type"),
                            ("URL", "url"),
                            ("BATCH", "batch_size"),
                        ],
                    )
                };
                format!("{}\n{t}", kv(&summary))
            })?;
        }
        AuditCmd::Put { file, tenant } => {
            let doc = read_json(&file)?;
            let v = ctx
                .api
                .send_json("PUT", "/_admin/audit", &tenant_query(&tenant), doc)
                .await?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Audit configuration stored ({} target(s))\n",
                    v["targets"].as_array().map_or(0, Vec::len)
                )
            })?;
        }
        AuditCmd::Delete { tenant } => {
            ctx.api
                .delete("/_admin/audit", &tenant_query(&tenant))
                .await?;
            ctx.out.done("Audit configuration removed")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tenant_provider_is_t_dash_lowercase() {
        assert_eq!(tenant_provider_name("Acme"), "t-acme");
    }

    #[test]
    fn the_sts_form_escapes_its_values() {
        let f = sts_form("arn:obio:iam::acme:role/r", "a.b+c", "s", Some(900));
        assert_eq!(
            f,
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&\
             RoleArn=arn%3Aobio%3Aiam%3A%3Aacme%3Arole%2Fr&WebIdentityToken=a.b%2Bc&\
             RoleSessionName=s&DurationSeconds=900"
        );
    }

    #[test]
    fn sts_credentials_come_out_of_the_xml() {
        let xml = "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>\
            <Credentials><AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>s</SecretAccessKey>\
            <SessionToken>t</SessionToken><Expiration>2026-09-14T13:00:00Z</Expiration></Credentials>\
            <AssumedRoleUser><Arn>arn:obio:sts::acme:assumed-role/r/s</Arn></AssumedRoleUser>\
            </AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>";
        let c = sts_credentials(xml).unwrap();
        assert_eq!(c["AccessKeyId"], "ASIA1");
        assert_eq!(c["AssumedRoleArn"], "arn:obio:sts::acme:assumed-role/r/s");
        assert!(sts_credentials("<x/>").is_err());
    }

    #[test]
    fn the_bucket_block_round_trips_through_xml() {
        let flags = PabFlags {
            block_public_policy: true,
            ..PabFlags::default()
        };
        let doc = pab_doc(&flags);
        assert_eq!(doc["BlockPublicPolicy"], true);
        assert_eq!(doc["BlockPublicAcls"], false);
        assert_eq!(pab_from_xml(&pab_xml(&doc)), doc);
        let all = pab_doc(&PabFlags {
            all: true,
            ..PabFlags::default()
        });
        assert!(PAB_FLAGS.iter().all(|k| all[k] == true));
    }
}
