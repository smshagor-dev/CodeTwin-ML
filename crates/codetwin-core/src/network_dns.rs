//! Authorized DNS resolution limited to explicitly approved private/loopback addresses.
//! This is a bounded system-resolver check, not subdomain enumeration.
use crate::network_inspection::safe_private_address;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, ToSocketAddrs},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsScope {
    pub authorized: bool,
    pub hostname: String,
    pub allowed_hostnames: Vec<String>,
    pub allowed_addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsObservation {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub note: String,
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

impl DnsScope {
    pub fn validate(&self) -> Result<(), String> {
        if !self.authorized {
            return Err("Explicit authorization is required before DNS inspection".into());
        }
        if !valid_hostname(&self.hostname) || self.hostname.parse::<IpAddr>().is_ok() {
            return Err("A valid DNS hostname, not a literal IP address, is required".into());
        }
        if self.allowed_hostnames.is_empty() || self.allowed_hostnames.len() > 16
            || !self.allowed_hostnames.iter().any(|name| name.eq_ignore_ascii_case(&self.hostname))
            || self.allowed_hostnames.iter().any(|name| !valid_hostname(name))
        {
            return Err("DNS hostname is outside the approved exact-name allowlist".into());
        }
        if self.allowed_addresses.is_empty()
            || self.allowed_addresses.len() > 16
            || self.allowed_addresses.iter().any(|ip| !safe_private_address(*ip))
        {
            return Err("Approved DNS addresses must be private or loopback IPs only".into());
        }
        Ok(())
    }
}

pub fn inspect_dns(scope: &DnsScope) -> Result<DnsObservation, String> {
    scope.validate()?;
    let addresses = (scope.hostname.as_str(), 0)
        .to_socket_addrs()
        .map_err(|_| "Authorized hostname could not be resolved".to_string())?
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>();
    if addresses.is_empty() || addresses.len() > 16 {
        return Err("DNS returned no usable addresses or exceeded the approved limit".into());
    }
    if addresses.iter().any(|ip| !scope.allowed_addresses.contains(ip)) {
        return Err("DNS response included an address outside the explicit allowlist".into());
    }
    Ok(DnsObservation {
        hostname: scope.hostname.to_ascii_lowercase(),
        addresses: addresses.into_iter().collect(),
        note: "Address-resolution check only; does not validate TLS, service availability, or DNSSEC".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn lab() -> DnsScope {
        DnsScope {
            authorized: true,
            hostname: "localhost".into(),
            allowed_hostnames: vec!["localhost".into()],
            allowed_addresses: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        }
    }

    #[test]
    fn fails_closed_on_scope_violations() {
        let mut config = lab();
        config.authorized = false;
        assert!(config.validate().is_err());
        config.authorized = true;
        config.hostname = "example.com".into();
        assert!(config.validate().is_err());
        config.allowed_hostnames = vec![config.hostname.clone()];
        config.allowed_addresses = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        assert!(config.validate().is_err());
        config.hostname = "invalid/host".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn localhost_dns_requires_every_returned_address_to_be_allowed() {
        let result = inspect_dns(&lab()).unwrap();
        assert!(!result.addresses.is_empty());
        assert!(result.addresses.iter().all(|ip| ip.is_loopback()));
        let mut limited = lab();
        limited.allowed_addresses.clear();
        limited.allowed_addresses.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        match inspect_dns(&limited) {
            Ok(value) => assert!(value.addresses.iter().all(|ip| ip.is_ipv4())),
            Err(error) => assert!(error.contains("allowlist")),
        }
    }
}
