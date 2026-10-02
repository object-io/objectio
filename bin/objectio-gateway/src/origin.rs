//! Where a request came from, for policies: the client's address
//! (`aws:SourceIp`) and the named endpoint it arrived on (`aws:SourceVpce`).
//!
//! Both come from the connection, never from what the client says. The one
//! exception is `X-Forwarded-For`, believed only as far back as the chain of
//! proxies the operator lists as trusted (`--trusted-proxies`): a load
//! balancer in front of the gateway is the peer every request arrives from,
//! and the client is the address it forwarded for.
//!
//! An endpoint is a data-plane listener with a name: `--endpoint-name` for
//! `--listen`, and `--data-listen ADDR=NAME` for more. Run one inside the
//! cluster and another behind the ingress, and a policy can tell them apart
//! — "readable without keys, but only from inside", or "this key works only
//! from inside". A listener without a name sets no `aws:SourceVpce`, as a
//! request over the internet has none in AWS.

use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};

use axum::http::{HeaderMap, Request};

/// The peer address of the connection a request arrived on.
#[derive(Clone, Copy, Debug)]
pub struct ClientAddr(pub SocketAddr);

/// The name of the endpoint (listener) a request arrived on.
#[derive(Clone, Debug, Default)]
pub struct Endpoint(pub Option<String>);

/// Proxies whose `X-Forwarded-For` is believed.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies(Vec<String>);

impl TrustedProxies {
    /// A comma-separated list of CIDRs or addresses.
    ///
    /// # Errors
    /// An entry that is neither.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut out = Vec::new();
        for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (addr, prefix) = entry.split_once('/').unwrap_or((entry, ""));
            let ip: IpAddr = addr
                .parse()
                .map_err(|_| format!("not an address or CIDR: {entry}"))?;
            if !prefix.is_empty() {
                let max = if ip.is_ipv4() { 32 } else { 128 };
                if prefix.parse::<u32>().map_or(true, |p| p > max) {
                    return Err(format!("bad prefix length: {entry}"));
                }
            }
            out.push(entry.to_string());
        }
        Ok(Self(out))
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        self.0
            .iter()
            .any(|cidr| objectio_auth::policy::cidr_contains(cidr, ip))
    }

    /// The client's address: the peer, or — when the peer is a trusted
    /// proxy — the nearest hop in `X-Forwarded-For` that isn't one.
    #[must_use]
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let mut ip = peer.to_canonical();
        if !self.contains(&ip) {
            return ip;
        }
        // Hops are appended left to right, each by the proxy that received
        // it; walk back from the nearest, through trusted proxies only.
        let hops: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        for hop in hops.iter().rev() {
            let Ok(hop) = hop.parse::<IpAddr>() else {
                // Garbage: stop at the last address known to be real.
                break;
            };
            ip = hop.to_canonical();
            if !self.contains(&ip) {
                break;
            }
        }
        ip
    }
}

/// Wraps a listener's service, putting each connection's peer address on
/// every request it carries.
#[derive(Clone)]
pub struct WithClientAddr<S> {
    pub inner: S,
    pub addr: SocketAddr,
}

impl<S, B> tower::Service<Request<B>> for WithClientAddr<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        request.extensions_mut().insert(ClientAddr(self.addr));
        self.inner.call(request)
    }
}

/// A valid endpoint name: short, plain, as it will be written in policies.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }

    #[test]
    fn a_direct_client_is_its_peer_whatever_it_claims() {
        let t = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(t.client_ip(peer, &xff("10.1.1.1")), peer);
        // No trusted proxies at all: never believe the header.
        let none = TrustedProxies::default();
        assert_eq!(none.client_ip(peer, &xff("10.1.1.1")), peer);
    }

    #[test]
    fn behind_trusted_proxies_the_client_is_the_first_untrusted_hop() {
        let t = TrustedProxies::parse("10.0.0.0/8, 192.168.1.1").unwrap();
        let lb: IpAddr = "10.0.0.5".parse().unwrap();
        // client, spoofed, real client, inner proxy
        let h = xff("1.1.1.1, 198.51.100.7, 192.168.1.1");
        assert_eq!(
            t.client_ip(lb, &h),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        // Garbage stops the walk at the last real address.
        assert_eq!(t.client_ip(lb, &xff("nonsense")), lb);
        // IPv4 seen as IPv6 is IPv4.
        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
        assert_eq!(
            t.client_ip(mapped, &xff("198.51.100.7")),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn bad_entries_and_names_are_refused() {
        assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
        assert!(TrustedProxies::parse("example.com").is_err());
        assert!(valid_name("internal") && valid_name("vpce-0a1b.edge"));
        assert!(!valid_name("") && !valid_name("in ternal") && !valid_name("a/b"));
    }
}
