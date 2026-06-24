//! Pod sandbox networking.
//!
//! Full CNI networking (per-pod netns + veth + routable IP) requires root, so a
//! rootless daemon falls back to **host networking**: rootless `crun` containers
//! share the host network namespace by default, so all containers in a pod (and
//! across pods) share networking and reach each other over `localhost`. The pod
//! IP reported to the kubelet is therefore the host's primary address.
//!
//! When this daemon later runs with root (e.g. inside a privileged kind/Docker
//! node), this module is where CNI plugin invocation + per-pod netns creation
//! would slot in.

/// How a sandbox's network is provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Share the host network namespace (rootless default; no CNI).
    Host,
}

/// Best-effort discovery of the host's primary outbound IPv4 address.
///
/// Uses a connected UDP socket: `connect` performs a routing-table lookup and
/// fixes the source address without sending any packets. Falls back to loopback
/// when no default route exists.
pub fn host_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_is_valid_ipv4() {
        let ip = host_ip();
        let parsed: std::net::Ipv4Addr = ip.parse().expect("host_ip returns a v4 address");
        // Either a routable address or the loopback fallback.
        assert!(!ip.is_empty());
        assert!(!parsed.is_unspecified());
    }
}
