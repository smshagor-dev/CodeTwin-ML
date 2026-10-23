//! Explicitly authorized, bounded TCP service reachability inspection.
//! No shell, raw packets, UDP flooding, banner grabbing or exploit payloads.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

const MAX_PORTS: usize = 32;
const MAX_WORKERS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScope {
    pub authorized: bool,
    pub target: IpAddr,
    pub allowed_addresses: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortObservation {
    pub port: u16,
    pub state: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInspection {
    pub target: IpAddr,
    pub observations: Vec<PortObservation>,
    pub tested_ports: usize,
    pub note: String,
}

fn safe_private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_loopback() || (v.is_private()
                && !v.is_broadcast()
                && !v.is_unspecified()
                && !v.is_link_local()
                && !v.is_multicast())
        }
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00 == 0xfc00
            && !v.is_unspecified() && !v.is_multicast()),
    }
}

impl NetworkScope {
    pub fn validate(&self) -> Result<Vec<u16>, String> {
        if !self.authorized {
            return Err("Explicit authorization is required before network inspection".into());
        }
        if !safe_private_address(self.target) {
            return Err("Only explicitly authorized loopback and private lab IPs are supported".into());
        }
        if self.allowed_addresses.is_empty()
            || self.allowed_addresses.len() > 16
            || !self.allowed_addresses.contains(&self.target)
            || self.allowed_addresses.iter().any(|ip| !safe_private_address(*ip))
        {
            return Err("Target must match the explicit private-address allowlist".into());
        }
        if self.ports.is_empty() || self.ports.len() > MAX_PORTS
            || !(100..=3000).contains(&self.timeout_ms)
        {
            return Err("Specify 1-32 ports and a 100-3000 ms connection timeout".into());
        }
        let ports: BTreeSet<_> = self.ports.iter().copied().collect();
        if ports.len() != self.ports.len() || ports.contains(&0) {
            return Err("Ports must be unique and between 1 and 65535".into());
        }
        Ok(ports.into_iter().collect())
    }
}

/// Inspect only explicit TCP ports. One connection attempt per port; no retries.
/// Each thread is joined and results are emitted in stable port order.
pub fn inspect_tcp(scope: &NetworkScope) -> Result<NetworkInspection, String> {
    let ports = scope.validate()?;
    let mut observations = Vec::with_capacity(ports.len());
    for chunk in ports.chunks(MAX_WORKERS) {
        let mut batch = Vec::with_capacity(chunk.len());
        thread::scope(|threads| {
            let handles = chunk.iter().map(|port| {
                let target = SocketAddr::new(scope.target, *port);
                threads.spawn(move || {
                    let started = Instant::now();
                    let state = match TcpStream::connect_timeout(
                        &target,
                        Duration::from_millis(scope.timeout_ms),
                    ) {
                        Ok(socket) => { drop(socket); "open" },
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => "closed",
                        Err(_) => "unreachable",
                    };
                    PortObservation {
                        port: target.port(),
                        state: state.to_string(),
                        elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    }
                })
            }).collect::<Vec<_>>();
            for handle in handles {
                batch.push(handle.join().map_err(|_| "Network worker panicked".to_string())?);
            }
            Ok::<(), String>(())
        })?;
        observations.extend(batch);
    }
    observations.sort_by_key(|value| value.port);
    Ok(NetworkInspection {
        target: scope.target,
        tested_ports: observations.len(),
        observations,
        note: "TCP connection reachability only; an open port does not prove service identity or vulnerability".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    fn scope(port: u16) -> NetworkScope {
        NetworkScope {
            authorized: true,
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allowed_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            ports: vec![port],
            timeout_ms: 500,
        }
    }

    #[test]
    fn reject_unapproved_public_and_ambiguous_targets() {
        let mut value = scope(443);
        value.authorized = false;
        assert!(value.validate().is_err());
        value.authorized = true;
        value.target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        value.allowed_addresses.push(value.target);
        assert!(value.validate().is_err());
        value.target = IpAddr::V4(Ipv4Addr::LOCALHOST);
        value.ports = vec![443, 443];
        assert!(value.validate().is_err());
        value.ports = vec![443; 33];
        assert!(value.validate().is_err());
    }

    #[test]
    fn bounded_loopback_listener_is_detected() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = inspect_tcp(&scope(port)).unwrap();
        assert_eq!(result.tested_ports, 1);
        assert_eq!(result.observations[0].state, "open");
    }

    #[test]
    fn scoped_two_port_scan_has_stable_order() {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let a = first.local_addr().unwrap().port();
        let b = second.local_addr().unwrap().port();
        let mut config = scope(a);
        config.ports.push(b);
        let result = inspect_tcp(&config).unwrap();
        assert_eq!(result.tested_ports, 2);
        assert!(result.observations.iter().all(|item| item.state == "open"));
        assert!(result.observations[0].port < result.observations[1].port);
    }
}
