//! Forming the meta nodes' Raft group, over their admin ports.
//!
//! The steps the Helm chart's bootstrap Job takes: `/init` on the first
//! node unless a group exists, then, on the leader, `/add-learner` for each
//! node not yet a voter and `/change-membership` with every node. Each
//! node's id and Raft address come from its own `/status`, so they are
//! what it was started with. Run again, it changes nothing.
//!
//! Under mTLS the admin ports are HTTPS and change membership only for a
//! client certificate of role admin, which `--tls-cert`, `--tls-key` and
//! `--tls-ca` give.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
struct Status {
    self_id: u64,
    self_addr: String,
    leader_id: Option<u64>,
    #[serde(default)]
    voters: Vec<u64>,
}

/// A client certificate for the admin ports, under mTLS: a certificate
/// of role admin, its key, and the CA that signed the meta nodes'.
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
}

impl Tls {
    fn client(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        let read = |p: &PathBuf| std::fs::read(p).with_context(|| format!("{}", p.display()));
        let ca = reqwest::Certificate::from_pem(&read(&self.ca)?).context("--tls-ca")?;
        let mut pem = read(&self.cert)?;
        pem.push(b'\n');
        pem.extend(read(&self.key)?);
        let identity = reqwest::Identity::from_pem(&pem).context("--tls-cert, --tls-key")?;
        Ok(builder
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity))
    }
}

/// `node` as an admin URL: `host`, `host:port` or a URL; `default_port`
/// when it names none, `default_scheme` when it names no scheme.
pub fn admin_url(node: &str, default_port: u16, default_scheme: &str) -> String {
    let (scheme, rest) = node
        .split_once("://")
        .map_or((default_scheme, node), |(s, r)| (s, r));
    let rest = rest.trim_end_matches('/');
    // An IPv6 literal is bracketed: its port follows the bracket.
    let has_port = match rest.rfind(']') {
        Some(end) => rest[end..].contains(':'),
        None => rest.contains(':'),
    };
    if has_port {
        format!("{scheme}://{rest}")
    } else {
        format!("{scheme}://{rest}:{default_port}")
    }
}

struct Admin {
    client: reqwest::Client,
    /// Whether it presents a certificate (mTLS).
    tls: bool,
}

impl Admin {
    async fn status(&self, url: &str) -> Result<Status> {
        Ok(self
            .client
            .get(format!("{url}/status"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// `url`'s status, waiting until `deadline` for it to answer.
    async fn await_status(&self, url: &str, deadline: Instant) -> Result<Status> {
        loop {
            match self.status(url).await {
                Ok(s) => return Ok(s),
                Err(e) if Instant::now() < deadline => {
                    info!("waiting for {url}: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    let hint = if self.tls {
                        ""
                    } else {
                        " (a cluster under mTLS takes HTTPS: pass --tls-cert, --tls-key and \
                         --tls-ca)"
                    };
                    return Err(e).with_context(|| format!("{url} never answered{hint}"));
                }
            }
        }
    }

    /// POST `body` to `url{path}`: its status code, failing on a transport
    /// error.
    async fn post(&self, url: &str, path: &str, body: serde_json::Value) -> Result<(u16, String)> {
        let r = self
            .client
            .post(format!("{url}{path}"))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{url}{path}"))?;
        let code = r.status().as_u16();
        Ok((code, r.text().await.unwrap_or_default()))
    }

    async fn post_ok(&self, url: &str, path: &str, body: serde_json::Value) -> Result<()> {
        let (code, text) = self.post(url, path, body).await?;
        if !(200..300).contains(&code) {
            bail!("{url}{path}: {code} {text}{}", refusal_hint(code));
        }
        Ok(())
    }
}

/// What to do about a refusal of the admin port's.
const fn refusal_hint(code: u16) -> &'static str {
    if code == 403 {
        " (under mTLS this takes a certificate of role admin: --tls-cert, --tls-key, --tls-ca)"
    } else {
        ""
    }
}

/// Make `nodes` (admin addresses, the first the one to start the group
/// from) one Raft group with every node a voter, waiting up to `wait` for
/// each to answer.
pub async fn init(
    nodes: &[String],
    default_port: u16,
    tls: Option<&Tls>,
    wait: Duration,
) -> Result<()> {
    if nodes.is_empty() {
        bail!("name every meta node's admin address");
    }
    let scheme = if tls.is_some() { "https" } else { "http" };
    let urls: Vec<String> = nodes
        .iter()
        .map(|n| admin_url(n, default_port, scheme))
        .collect();
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(60));
    if let Some(tls) = tls {
        builder = tls.client(builder)?;
    }
    let admin = Admin {
        client: builder.build()?,
        tls: tls.is_some(),
    };
    let deadline = Instant::now() + wait;

    let mut statuses = Vec::new();
    for url in &urls {
        let s = admin.await_status(url, deadline).await?;
        if s.self_addr.starts_with("0.0.0.0") || s.self_addr.starts_with("[::]") {
            bail!(
                "{url} advertises {} to its peers: start it with --raft-advertise <address the others reach it at>",
                s.self_addr
            );
        }
        info!("{url}: node {} at {}", s.self_id, s.self_addr);
        statuses.push(s);
    }
    let mut ids: Vec<u64> = statuses.iter().map(|s| s.self_id).collect();
    ids.sort_unstable();
    if let Some(w) = ids.windows(2).find(|w| w[0] == w[1]) {
        bail!(
            "two of the nodes have node id {}: each needs its own --node-id",
            w[0]
        );
    }

    if statuses[0].voters.is_empty() {
        let (code, text) = admin.post(&urls[0], "/init", serde_json::json!({})).await?;
        match code {
            200 => info!("node {} started the group", statuses[0].self_id),
            409 => info!("node {} has a group already", statuses[0].self_id),
            _ => bail!("{}/init: {code} {text}{}", urls[0], refusal_hint(code)),
        }
    }

    let leader = loop {
        let s = admin.status(&urls[0]).await?;
        if let Some(id) = s.leader_id {
            break id;
        }
        if Instant::now() > deadline {
            bail!("no Raft leader known to {}", urls[0]);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let Some(leader_url) = statuses
        .iter()
        .position(|s| s.self_id == leader)
        .map(|i| &urls[i])
    else {
        bail!("the leader, node {leader}, is not one of the nodes named: name every meta node");
    };
    let mut voters = admin.status(leader_url).await?.voters;
    voters.sort_unstable();
    if let Some(v) = voters.iter().find(|v| !ids.contains(v)) {
        bail!(
            "node {v} is a voter but not one of the nodes named: name every meta node \
             (a node is taken out with /change-membership, by hand)"
        );
    }
    if voters == ids {
        info!("every node is a voter already");
    } else {
        for s in statuses.iter().filter(|s| !voters.contains(&s.self_id)) {
            info!("adding node {} at {}", s.self_id, s.self_addr);
            admin
                .post_ok(
                    leader_url,
                    "/add-learner",
                    serde_json::json!({ "node_id": s.self_id, "addr": s.self_addr }),
                )
                .await?;
        }
        admin
            .post_ok(
                leader_url,
                "/change-membership",
                serde_json::json!({ "voters": ids }),
            )
            .await?;
    }
    let s = admin.status(leader_url).await?;
    println!(
        "Raft group formed: voters {:?}, leader node {}",
        s.voters,
        s.leader_id
            .map_or_else(|| "unknown".into(), |l| l.to_string())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::admin_url;

    #[test]
    fn a_node_is_named_by_host_and_port_or_url() {
        assert_eq!(admin_url("meta1", 9102, "http"), "http://meta1:9102");
        assert_eq!(admin_url("meta1:19102", 9102, "http"), "http://meta1:19102");
        assert_eq!(
            admin_url("http://meta1/", 9102, "http"),
            "http://meta1:9102"
        );
        assert_eq!(
            admin_url("https://meta1:1", 9102, "http"),
            "https://meta1:1"
        );
        assert_eq!(
            admin_url("[fd00::1]", 9102, "http"),
            "http://[fd00::1]:9102"
        );
        assert_eq!(admin_url("[fd00::1]:5", 9102, "http"), "http://[fd00::1]:5");
        // Under mTLS (a client certificate given), HTTPS unless named.
        assert_eq!(admin_url("meta1", 9102, "https"), "https://meta1:9102");
        assert_eq!(
            admin_url("http://meta1", 9102, "https"),
            "http://meta1:9102"
        );
    }
}
