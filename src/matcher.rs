#![allow(dead_code)]

use std::net::IpAddr;

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// 检查 IP 是否在 CIDR 范围内
pub fn ip_in_network(ip: IpAddr, network: &IpNetwork) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip4), IpNetwork::V4(net4)) => net4.contains(ip4),
        (IpAddr::V6(ip6), IpNetwork::V6(net6)) => net6.contains(ip6),
        _ => false, // IPv4 vs IPv6 不匹配
    }
}

/// 检查 IP 是否在 Ipv4Network 中（可选 CIDR 掩码覆盖）
pub fn ip_in_ipv4_network(ip: IpAddr, network: &Ipv4Network, cidr_override: Option<u8>) -> bool {
    match ip {
        IpAddr::V4(ip4) => {
            if let Some(cidr) = cidr_override {
                if let Ok(adjusted) = Ipv4Network::new(network.ip(), cidr) {
                    return adjusted.contains(ip4);
                }
            }
            network.contains(ip4)
        }
        IpAddr::V6(_) => false,
    }
}

/// 检查 IP 是否在 Ipv6Network 中（可选 CIDR 掩码覆盖）
pub fn ip_in_ipv6_network(ip: IpAddr, network: &Ipv6Network, cidr_override: Option<u8>) -> bool {
    match ip {
        IpAddr::V6(ip6) => {
            if let Some(cidr) = cidr_override {
                if let Ok(adjusted) = Ipv6Network::new(network.ip(), cidr) {
                    return adjusted.contains(ip6);
                }
            }
            network.contains(ip6)
        }
        IpAddr::V4(_) => false,
    }
}

/// 检查 IP 是否在给定 IP 列表中（应用 CIDR4/CIDR6 掩码）
/// 用于 a/mx 机制：解析出的 IP 列表需要根据 CIDR 掩码调整后匹配
pub fn ip_in_resolved_ips(
    check_ip: IpAddr,
    resolved_ips: &[IpAddr],
    cidr4: Option<u8>,
    cidr6: Option<u8>,
) -> bool {
    for ip in resolved_ips {
        // 如果解析出的 IP 与目标 IP 类型不同，跳过
        if check_ip.is_ipv4() != ip.is_ipv4() {
            continue;
        }

        match (check_ip, ip) {
            (IpAddr::V4(target), IpAddr::V4(resolved)) => {
                let prefix = cidr4.unwrap_or(32);
                if let Ok(network) = Ipv4Network::new(*resolved, prefix) {
                    if network.contains(target) {
                        return true;
                    }
                }
            }
            (IpAddr::V6(target), IpAddr::V6(resolved)) => {
                let prefix = cidr6.unwrap_or(128);
                if let Ok(network) = Ipv6Network::new(*resolved, prefix) {
                    if network.contains(target) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip_in_network_v4() {
        let net: IpNetwork = "192.168.1.0/24".parse().unwrap();
        assert!(ip_in_network(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            &net
        ));
        assert!(!ip_in_network(
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)),
            &net
        ));
    }

    #[test]
    fn test_ip_in_network_v6() {
        let net: IpNetwork = "2001:db8::/32".parse().unwrap();
        assert!(ip_in_network(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &net
        ));
        assert!(!ip_in_network(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)),
            &net
        ));
    }

    #[test]
    fn test_ip_in_network_cross_family() {
        let net: IpNetwork = "192.168.1.0/24".parse().unwrap();
        assert!(!ip_in_network(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &net
        ));
    }

    #[test]
    fn test_ip_in_resolved_ips_with_cidr() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        ];
        // 10.0.0.1/8 → 10.0.0.0/8 → 10.1.2.3 in range
        assert!(ip_in_resolved_ips(
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            &ips,
            Some(8),
            None
        ));
        // 192.168.1.1/32 → only exact match
        assert!(ip_in_resolved_ips(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            &ips,
            None,
            None
        ));
        assert!(!ip_in_resolved_ips(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            &ips,
            None,
            None
        ));
    }

    #[test]
    fn test_ip_in_resolved_ips_v6() {
        let ips = vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))];
        assert!(ip_in_resolved_ips(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42)),
            &ips,
            None,
            Some(64)
        ));
    }

    #[test]
    fn test_cidr_zero() {
        // /0 matches everything
        let ips = vec![IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))];
        assert!(ip_in_resolved_ips(
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            &ips,
            Some(0),
            None
        ));
    }
}
