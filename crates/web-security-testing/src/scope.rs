use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use thiserror::Error;
use url::Url;

use crate::ScopeConfig;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("authorization confirmation is required before active web security testing")]
    AuthorizationRequired,
    #[error("invalid target URL: {0}")]
    InvalidTarget(String),
    #[error("URL is outside the authorized scope: {0}")]
    OutsideScope(String),
    #[error("target address is not allowed by the configured network scope: {0}")]
    NetworkScope(String),
    #[error("target hostname could not be resolved: {0}")]
    Resolution(String),
}

#[derive(Debug, Clone)]
pub struct ScopePolicy {
    config: ScopeConfig,
    target: Url,
    target_host: String,
    target_port: u16,
}

impl ScopePolicy {
    pub fn new(mut config: ScopeConfig) -> Result<Self, ScopeError> {
        if !config.authorization_confirmed {
            return Err(ScopeError::AuthorizationRequired);
        }
        config.max_crawl_depth = config.max_crawl_depth.min(8);
        config.max_requests = config.max_requests.clamp(1, 2_000);
        config.concurrency = config.concurrency.clamp(1, 8);
        config.timeout_ms = config.timeout_ms.clamp(500, 30_000);
        config.response_limit_bytes = config.response_limit_bytes.clamp(16_384, 2_097_152);
        config.redirect_limit = config.redirect_limit.min(8);
        config.retry_limit = config.retry_limit.min(2);
        // Timing/delay probes are intentionally disabled by the strict active-payload policy.
        // Keep the field for backward-compatible persisted configs, but never execute them.
        config.enable_timing_probes = false;

        let target = normalize_url(&config.target_url)?;
        let target_host = target
            .host_str()
            .ok_or_else(|| ScopeError::InvalidTarget("target must contain a hostname".to_string()))?
            .to_ascii_lowercase();
        let target_port = target.port_or_known_default().ok_or_else(|| {
            ScopeError::InvalidTarget("target scheme must have a known or explicit port".to_string())
        })?;

        if config.allowed_hostnames.is_empty() {
            config.allowed_hostnames.push(target_host.clone());
        }
        config.allowed_hostnames = normalize_hosts(&config.allowed_hostnames);
        config.allowed_subdomains = normalize_hosts(&config.allowed_subdomains);
        if config.allowed_paths.is_empty() {
            config.allowed_paths.push("/".to_string());
        }
        config.allowed_paths = normalize_paths(&config.allowed_paths);
        config.excluded_paths = normalize_paths(&config.excluded_paths);

        let policy = Self {
            config,
            target,
            target_host,
            target_port,
        };
        policy.assert_url(&policy.target)?;
        policy.resolve_and_pin(&policy.target)?;
        Ok(policy)
    }

    pub fn config(&self) -> &ScopeConfig {
        &self.config
    }

    pub fn target(&self) -> &Url {
        &self.target
    }

    pub fn credentials_allowed_for(&self, url: &Url) -> bool {
        self.assert_url(url).is_ok()
            && url.host_str().is_some_and(|host| host.eq_ignore_ascii_case(&self.target_host))
            && url.port_or_known_default() == Some(self.target_port)
            && url.scheme() == self.target.scheme()
    }

    pub fn normalize_and_assert(&self, raw: &str) -> Result<Url, ScopeError> {
        let url = normalize_url(raw)?;
        self.assert_url(&url)?;
        Ok(url)
    }

    pub fn assert_url(&self, url: &Url) -> Result<(), ScopeError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ScopeError::OutsideScope("URL scheme is outside the authorized HTTP(S) scope".to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ScopeError::OutsideScope("credentials in URLs are forbidden".to_string()));
        }
        let host = url
            .host_str()
            .ok_or_else(|| ScopeError::OutsideScope("URL is outside the authorized scope".to_string()))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !self.host_allowed(&host) {
            return Err(ScopeError::OutsideScope("URL host is outside the authorized host scope".to_string()));
        }
        let port = url.port_or_known_default().ok_or_else(|| ScopeError::OutsideScope(url.to_string()))?;
        if port != self.target_port {
            return Err(ScopeError::OutsideScope(format!("port {port} is outside the authorized target port")));
        }
        if self.target.scheme() == "https" && url.scheme() != "https" {
            return Err(ScopeError::OutsideScope("HTTPS target cannot downgrade to HTTP".to_string()));
        }
        if !self.path_allowed(url.path()) {
            return Err(ScopeError::OutsideScope("URL path is outside the authorized path scope".to_string()));
        }
        Ok(())
    }

    pub fn resolve_and_pin(&self, url: &Url) -> Result<SocketAddr, ScopeError> {
        self.assert_url(url)?;
        let host = url.host_str().ok_or_else(|| ScopeError::Resolution("URL host is missing".to_string()))?;
        let port = url.port_or_known_default().ok_or_else(|| ScopeError::Resolution(url.to_string()))?;
        let addresses: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|error| ScopeError::Resolution(error.to_string()))?
            .collect();
        if addresses.is_empty() {
            return Err(ScopeError::Resolution(format!("no address for {host}")));
        }
        for address in &addresses {
            self.assert_ip(address.ip(), host)?;
        }
        Ok(addresses[0])
    }

    fn host_allowed(&self, host: &str) -> bool {
        if host == self.target_host {
            return true;
        }
        if self.config.allowed_hostnames.iter().any(|allowed| host == allowed) {
            return true;
        }
        self.config.allowed_subdomains.iter().any(|root| {
            host != root && host.ends_with(&format!(".{root}"))
        })
    }

    fn path_allowed(&self, path: &str) -> bool {
        let included = self.config.allowed_paths.iter().any(|prefix| path_prefix(path, prefix));
        let excluded = self.config.excluded_paths.iter().any(|prefix| path_prefix(path, prefix));
        included && !excluded
    }

    fn assert_ip(&self, ip: IpAddr, host: &str) -> Result<(), ScopeError> {
        if is_unroutable(ip) {
            return Err(ScopeError::NetworkScope(format!("{host} resolved to blocked address {ip}")));
        }
        let local_target = matches!(host, "localhost")
            || host.ends_with(".localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if is_loopback_or_private(ip) && !(local_target || self.config.allow_private_networks) {
            return Err(ScopeError::NetworkScope(format!(
                "{host} resolved to private/loopback address {ip}; enable private-network testing explicitly for an authorized local or staging target"
            )));
        }
        Ok(())
    }
}

pub fn normalize_url(raw: &str) -> Result<Url, ScopeError> {
    let trimmed = raw.trim();
    let mut url = Url::parse(trimmed).map_err(|error| ScopeError::InvalidTarget(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ScopeError::InvalidTarget("only http:// and https:// are supported".to_string()));
    }
    if url.host_str().is_none() {
        return Err(ScopeError::InvalidTarget("target must contain a hostname".to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ScopeError::InvalidTarget("credentials in the target URL are forbidden".to_string()));
    }
    url.set_fragment(None);
    Ok(url)
}

fn normalize_hosts(values: &[String]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| value.trim().trim_matches('.').to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

fn normalize_paths(values: &[String]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| {
            let value = value.trim();
            if value.starts_with('/') { value.to_string() } else { format!("/{value}") }
        })
        .collect();
    values.sort();
    values.dedup();
    values
}

fn path_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/" || path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
}

fn is_unroutable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_link_local()
                || ip == Ipv4Addr::new(169, 254, 169, 254)
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
        }
    }
}

fn is_loopback_or_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || is_unique_local_v6(ip),
    }
}

fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::{normalize_url, ScopePolicy};
    use crate::ScopeConfig;
    use url::Url;

    fn config() -> ScopeConfig {
        ScopeConfig {
            target_url: "http://localhost:8080/app".into(),
            allowed_hostnames: vec!["localhost".into()],
            allowed_subdomains: vec![],
            allowed_paths: vec!["/app".into()],
            excluded_paths: vec!["/app/logout".into()],
            max_crawl_depth: 3,
            max_requests: 100,
            concurrency: 2,
            timeout_ms: 3_000,
            response_limit_bytes: 128_000,
            redirect_limit: 3,
            retry_limit: 0,
            active_testing: true,
            allow_non_idempotent_methods: false,
            allow_private_networks: true,
            enable_timing_probes: false,
            authorization_confirmed: true,
        }
    }

    #[test]
    fn normalizes_and_enforces_paths_and_hosts() {
        let policy = ScopePolicy::new(config()).expect("scope");
        assert!(policy.normalize_and_assert("http://localhost:8080/app/users?id=1").is_ok());
        assert!(policy.normalize_and_assert("http://localhost:8080/app/logout").is_err());
        assert!(policy.normalize_and_assert("http://example.com:8080/app").is_err());
        assert!(normalize_url("file:///tmp/a").is_err());
        let target = policy
            .normalize_and_assert("http://localhost:8080/app/users")
            .expect("target");
        assert!(policy.credentials_allowed_for(&target));

        let mut alternate = config();
        alternate.allowed_hostnames.push("127.0.0.1".into());
        let alternate_policy = ScopePolicy::new(alternate).expect("alternate scope");
        let sibling = Url::parse("http://127.0.0.1:8080/app/users").expect("sibling");
        assert!(alternate_policy.assert_url(&sibling).is_ok());
        assert!(!alternate_policy.credentials_allowed_for(&sibling));
    }

    #[test]
    fn strict_scope_policy_disables_timing_probes_even_for_legacy_configs() {
        let mut value = config();
        value.enable_timing_probes = true;
        let policy = ScopePolicy::new(value).expect("scope");
        assert!(!policy.config().enable_timing_probes);
    }

    #[test]
    fn authorization_is_mandatory() {
        let mut value = config();
        value.authorization_confirmed = false;
        assert!(ScopePolicy::new(value).is_err());
    }
}
