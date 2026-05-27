#![allow(dead_code)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::error::{SpfError, SpfResult};

/// SPF 限定符：决定机制匹配时的处置方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Pass,     // +
    Fail,     // -
    SoftFail, // ~
    Neutral,  // ?
}

impl Qualifier {
    /// 将字符解析为 Qualifier，'+' 为默认值
    fn from_prefix(c: char) -> Option<Self> {
        match c {
            '+' => Some(Self::Pass),
            '-' => Some(Self::Fail),
            '~' => Some(Self::SoftFail),
            '?' => Some(Self::Neutral),
            _ => None,
        }
    }

    pub fn symbol(&self) -> char {
        match self {
            Self::Pass => '+',
            Self::Fail => '-',
            Self::SoftFail => '~',
            Self::Neutral => '?',
        }
    }
}

impl fmt::Display for Qualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

/// SPF 机制（mechanism）
#[derive(Debug, Clone)]
pub enum Mechanism {
    All {
        qualifier: Qualifier,
    },
    Include {
        qualifier: Qualifier,
        domain: String,
    },
    A {
        qualifier: Qualifier,
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    Mx {
        qualifier: Qualifier,
        domain: Option<String>,
        cidr4: Option<u8>,
        cidr6: Option<u8>,
    },
    Ip4 {
        qualifier: Qualifier,
        network: Ipv4Network,
    },
    Ip6 {
        qualifier: Qualifier,
        network: Ipv6Network,
    },
    Ptr {
        qualifier: Qualifier,
        domain: Option<String>,
    },
    Exists {
        qualifier: Qualifier,
        domain: String,
    },
}

impl Mechanism {
    pub fn qualifier(&self) -> Qualifier {
        match self {
            Self::All { qualifier }
            | Self::Include { qualifier, .. }
            | Self::A { qualifier, .. }
            | Self::Mx { qualifier, .. }
            | Self::Ip4 { qualifier, .. }
            | Self::Ip6 { qualifier, .. }
            | Self::Ptr { qualifier, .. }
            | Self::Exists { qualifier, .. } => *qualifier,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::All { .. } => "all",
            Self::Include { .. } => "include",
            Self::A { .. } => "a",
            Self::Mx { .. } => "mx",
            Self::Ip4 { .. } => "ip4",
            Self::Ip6 { .. } => "ip6",
            Self::Ptr { .. } => "ptr",
            Self::Exists { .. } => "exists",
        }
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let q = self.qualifier();
        let prefix = if q == Qualifier::Pass {
            String::new()
        } else {
            q.symbol().to_string()
        };

        match self {
            Self::All { .. } => write!(f, "{prefix}all"),
            Self::Include { domain, .. } => write!(f, "{prefix}include:{domain}"),
            Self::A {
                domain,
                cidr4,
                cidr6,
                ..
            } => {
                write!(f, "{prefix}a")?;
                if let Some(d) = domain {
                    write!(f, ":{d}")?;
                }
                if let Some(c4) = cidr4 {
                    write!(f, "/{c4}")?;
                }
                if let Some(c6) = cidr6 {
                    write!(f, "//{c6}")?;
                }
                Ok(())
            }
            Self::Mx {
                domain,
                cidr4,
                cidr6,
                ..
            } => {
                write!(f, "{prefix}mx")?;
                if let Some(d) = domain {
                    write!(f, ":{d}")?;
                }
                if let Some(c4) = cidr4 {
                    write!(f, "/{c4}")?;
                }
                if let Some(c6) = cidr6 {
                    write!(f, "//{c6}")?;
                }
                Ok(())
            }
            Self::Ip4 { network, .. } => write!(f, "{prefix}ip4:{network}"),
            Self::Ip6 { network, .. } => write!(f, "{prefix}ip6:{network}"),
            Self::Ptr { domain, .. } => {
                write!(f, "{prefix}ptr")?;
                if let Some(d) = domain {
                    write!(f, ":{d}")?;
                }
                Ok(())
            }
            Self::Exists { domain, .. } => write!(f, "{prefix}exists:{domain}"),
        }
    }
}

/// SPF 修饰符（modifier）
#[derive(Debug, Clone)]
pub enum Modifier {
    Redirect { domain: String },
    Exp { domain: String },
}

/// 解析后的 SPF 记录
#[derive(Debug, Clone)]
pub struct SpfRecord {
    pub mechanisms: Vec<Mechanism>,
    pub modifiers: Vec<Modifier>,
    pub raw: String,
}

impl SpfRecord {
    pub fn has_all_mechanism(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| matches!(m, Mechanism::All { .. }))
    }

    pub fn redirect_domain(&self) -> Option<&str> {
        self.modifiers.iter().find_map(|m| match m {
            Modifier::Redirect { domain } => Some(domain.as_str()),
            _ => None,
        })
    }
}

/// 解析 SPF TXT 记录
pub fn parse_spf(txt: &str) -> SpfResult<SpfRecord> {
    let trimmed = txt.trim();

    if !trimmed.starts_with("v=spf1") {
        return Err(SpfError::MalformedSpf {
            domain: String::new(),
            reason: "记录不以 v=spf1 开头".into(),
        });
    }

    // v=spf1 后必须是空格或字符串结束
    let rest = &trimmed[6..];
    if !rest.is_empty() && !rest.starts_with(' ') && !rest.starts_with('\t') {
        return Err(SpfError::MalformedSpf {
            domain: String::new(),
            reason: "v=spf1 后必须为空格".into(),
        });
    }

    let mut mechanisms = Vec::new();
    let mut modifiers = Vec::new();

    for term in rest.split_whitespace() {
        if term.contains('=') {
            // 修饰符
            if let Some(modifier) = parse_modifier(term) {
                modifiers.push(modifier);
            }
            // 未知修饰符忽略（RFC 7208 §6）
        } else {
            // 机制
            let mechanism = parse_mechanism(term)?;
            mechanisms.push(mechanism);
        }
    }

    Ok(SpfRecord {
        mechanisms,
        modifiers,
        raw: trimmed.to_string(),
    })
}

fn parse_modifier(term: &str) -> Option<Modifier> {
    if let Some(domain) = term.strip_prefix("redirect=") {
        Some(Modifier::Redirect {
            domain: domain.to_lowercase(),
        })
    } else if let Some(domain) = term.strip_prefix("exp=") {
        Some(Modifier::Exp {
            domain: domain.to_lowercase(),
        })
    } else {
        None
    }
}

fn parse_mechanism(term: &str) -> SpfResult<Mechanism> {
    let (qualifier, body) = extract_qualifier(term);

    if body == "all" {
        return Ok(Mechanism::All { qualifier });
    }

    if let Some(domain) = body.strip_prefix("include:") {
        return Ok(Mechanism::Include {
            qualifier,
            domain: domain.to_lowercase(),
        });
    }

    if body == "a" || body.starts_with("a:") || body.starts_with("a/") {
        return parse_a_mechanism(qualifier, body);
    }

    if body == "mx" || body.starts_with("mx:") || body.starts_with("mx/") {
        return parse_mx_mechanism(qualifier, body);
    }

    if let Some(value) = body.strip_prefix("ip4:") {
        return parse_ip4(qualifier, value);
    }

    if let Some(value) = body.strip_prefix("ip6:") {
        return parse_ip6(qualifier, value);
    }

    if body == "ptr" || body.starts_with("ptr:") {
        let domain = body.strip_prefix("ptr:").map(|d| d.to_lowercase());
        return Ok(Mechanism::Ptr { qualifier, domain });
    }

    if let Some(domain) = body.strip_prefix("exists:") {
        return Ok(Mechanism::Exists {
            qualifier,
            domain: domain.to_lowercase(),
        });
    }

    Err(SpfError::MalformedSpf {
        domain: String::new(),
        reason: format!("未知机制: {body}"),
    })
}

fn extract_qualifier(term: &str) -> (Qualifier, &str) {
    let mut chars = term.chars();
    if let Some(first) = chars.next() {
        if let Some(q) = Qualifier::from_prefix(first) {
            return (q, chars.as_str());
        }
    }
    (Qualifier::Pass, term)
}

/// 解析 a 机制：a | a:domain | a/cidr | a:domain/cidr | a:domain/cidr4//cidr6
fn parse_a_mechanism(qualifier: Qualifier, body: &str) -> SpfResult<Mechanism> {
    let (domain_part, cidr4, cidr6) = parse_domain_cidr(body, "a")?;
    Ok(Mechanism::A {
        qualifier,
        domain: domain_part,
        cidr4,
        cidr6,
    })
}

/// 解析 mx 机制：mx | mx:domain | mx/cidr | mx:domain/cidr | mx:domain/cidr4//cidr6
fn parse_mx_mechanism(qualifier: Qualifier, body: &str) -> SpfResult<Mechanism> {
    let (domain_part, cidr4, cidr6) = parse_domain_cidr(body, "mx")?;
    Ok(Mechanism::Mx {
        qualifier,
        domain: domain_part,
        cidr4,
        cidr6,
    })
}

/// 解析 "机制名:domain/cidr4//cidr6" 格式
/// 返回 (domain, cidr4, cidr6)，domain 为 None 表示使用当前域名
fn parse_domain_cidr(
    body: &str,
    mechanism_name: &str,
) -> SpfResult<(Option<String>, Option<u8>, Option<u8>)> {
    let value = body
        .strip_prefix(&format!("{mechanism_name}:"))
        .unwrap_or(body);

    // 检查是否有 // (双 CIDR)
    if let Some(dual_pos) = value.find("//") {
        let before_dual = &value[..dual_pos];
        let after_dual = &value[dual_pos + 2..];

        let cidr6: u8 = after_dual
            .parse()
            .map_err(|_| SpfError::InvalidCidr(after_dual.to_string()))?;

        // 在 // 之前查找单个 /
        let (domain, cidr4) = if let Some(single_pos) = before_dual.rfind('/') {
            let d = &before_dual[..single_pos];
            let c4: u8 = before_dual[single_pos + 1..]
                .parse()
                .map_err(|_| SpfError::InvalidCidr(before_dual[single_pos + 1..].to_string()))?;
            (
                if d.is_empty() {
                    None
                } else {
                    Some(d.to_lowercase())
                },
                Some(c4),
            )
        } else {
            (
                if before_dual.is_empty() {
                    None
                } else {
                    Some(before_dual.to_lowercase())
                },
                None,
            )
        };

        return Ok((domain, cidr4, Some(cidr6)));
    }

    // 单个 / (或没有 /)
    if let Some(slash_pos) = value.rfind('/') {
        let domain = &value[..slash_pos];
        let cidr_str = &value[slash_pos + 1..];
        let cidr4: u8 = cidr_str
            .parse()
            .map_err(|_| SpfError::InvalidCidr(cidr_str.to_string()))?;
        let domain = if domain.is_empty() {
            None
        } else {
            Some(domain.to_lowercase())
        };
        Ok((domain, Some(cidr4), None))
    } else {
        let domain = if value.is_empty() || value == mechanism_name {
            None
        } else {
            Some(value.to_lowercase())
        };
        Ok((domain, None, None))
    }
}

fn parse_ip4(qualifier: Qualifier, value: &str) -> SpfResult<Mechanism> {
    let network = if value.contains('/') {
        value
            .parse::<Ipv4Network>()
            .map_err(|e| SpfError::InvalidCidr(format!("{value}: {e}")))?
    } else {
        let ip: Ipv4Addr = value
            .parse()
            .map_err(|e| SpfError::InvalidIp(format!("{value}: {e}")))?;
        Ipv4Network::new(ip, 32).unwrap()
    };
    Ok(Mechanism::Ip4 { qualifier, network })
}

fn parse_ip6(qualifier: Qualifier, value: &str) -> SpfResult<Mechanism> {
    let network = if value.contains('/') {
        value
            .parse::<Ipv6Network>()
            .map_err(|e| SpfError::InvalidCidr(format!("{value}: {e}")))?
    } else {
        let ip: Ipv6Addr = value
            .parse()
            .map_err(|e| SpfError::InvalidIp(format!("{value}: {e}")))?;
        Ipv6Network::new(ip, 128).unwrap()
    };
    Ok(Mechanism::Ip6 { qualifier, network })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_spf() {
        let record = parse_spf("v=spf1 ip4:192.168.1.0/24 -all").unwrap();
        assert_eq!(record.mechanisms.len(), 2);
        assert!(matches!(record.mechanisms[0], Mechanism::Ip4 { .. }));
        assert!(matches!(
            record.mechanisms[1],
            Mechanism::All {
                qualifier: Qualifier::Fail
            }
        ));
    }

    #[test]
    fn test_parse_include() {
        let record = parse_spf("v=spf1 include:_spf.google.com ~all").unwrap();
        assert_eq!(record.mechanisms.len(), 2);
        match &record.mechanisms[0] {
            Mechanism::Include { qualifier, domain } => {
                assert_eq!(*qualifier, Qualifier::Pass);
                assert_eq!(domain, "_spf.google.com");
            }
            _ => panic!("Expected Include mechanism"),
        }
    }

    #[test]
    fn test_parse_a_mechanism_variants() {
        // bare a
        let r = parse_spf("v=spf1 a").unwrap();
        match &r.mechanisms[0] {
            Mechanism::A {
                domain,
                cidr4,
                cidr6,
                ..
            } => {
                assert!(domain.is_none());
                assert!(cidr4.is_none());
                assert!(cidr6.is_none());
            }
            _ => panic!(),
        }

        // a:domain
        let r = parse_spf("v=spf1 a:example.com").unwrap();
        match &r.mechanisms[0] {
            Mechanism::A { domain, cidr4, .. } => {
                assert_eq!(domain.as_deref(), Some("example.com"));
                assert!(cidr4.is_none());
            }
            _ => panic!(),
        }

        // a:domain/cidr
        let r = parse_spf("v=spf1 a:example.com/24").unwrap();
        match &r.mechanisms[0] {
            Mechanism::A { domain, cidr4, .. } => {
                assert_eq!(domain.as_deref(), Some("example.com"));
                assert_eq!(*cidr4, Some(24));
            }
            _ => panic!(),
        }

        // a:domain/cidr4//cidr6
        let r = parse_spf("v=spf1 a:example.com/24//96").unwrap();
        match &r.mechanisms[0] {
            Mechanism::A {
                domain,
                cidr4,
                cidr6,
                ..
            } => {
                assert_eq!(domain.as_deref(), Some("example.com"));
                assert_eq!(*cidr4, Some(24));
                assert_eq!(*cidr6, Some(96));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_mx_mechanism() {
        let r = parse_spf("v=spf1 mx mx:mail.example.com/16 -all").unwrap();
        assert_eq!(r.mechanisms.len(), 3);

        match &r.mechanisms[0] {
            Mechanism::Mx { domain, .. } => assert!(domain.is_none()),
            _ => panic!(),
        }
        match &r.mechanisms[1] {
            Mechanism::Mx { domain, cidr4, .. } => {
                assert_eq!(domain.as_deref(), Some("mail.example.com"));
                assert_eq!(*cidr4, Some(16));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_ip4() {
        let r = parse_spf("v=spf1 ip4:10.0.0.0/8 ip4:172.16.0.1 -all").unwrap();
        match &r.mechanisms[0] {
            Mechanism::Ip4 { network, .. } => {
                assert_eq!(network.prefix(), 8);
                assert_eq!(network.ip(), Ipv4Addr::new(10, 0, 0, 0));
            }
            _ => panic!(),
        }
        match &r.mechanisms[1] {
            Mechanism::Ip4 { network, .. } => {
                assert_eq!(network.prefix(), 32);
                assert_eq!(network.ip(), Ipv4Addr::new(172, 16, 0, 1));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_ip6() {
        let r = parse_spf("v=spf1 ip6:2001:db8::/32 -all").unwrap();
        match &r.mechanisms[0] {
            Mechanism::Ip6 { network, .. } => {
                assert_eq!(network.prefix(), 32);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_ptr() {
        let r = parse_spf("v=spf1 ptr ptr:example.com -all").unwrap();
        match &r.mechanisms[0] {
            Mechanism::Ptr { domain, .. } => assert!(domain.is_none()),
            _ => panic!(),
        }
        match &r.mechanisms[1] {
            Mechanism::Ptr { domain, .. } => {
                assert_eq!(domain.as_deref(), Some("example.com"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_exists() {
        let r = parse_spf("v=spf1 exists:%{ir}.%{l1r+-}._spf.hotmail.com -all").unwrap();
        match &r.mechanisms[0] {
            Mechanism::Exists { domain, .. } => {
                assert_eq!(domain, "%{ir}.%{l1r+-}._spf.hotmail.com");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_parse_redirect() {
        let r = parse_spf("v=spf1 redirect=_spf.example.com").unwrap();
        assert!(r.mechanisms.is_empty());
        assert_eq!(r.redirect_domain(), Some("_spf.example.com"));
    }

    #[test]
    fn test_parse_qualifiers() {
        let r = parse_spf("v=spf1 +ip4:1.0.0.0/8 -ip4:2.0.0.0/8 ~ip4:3.0.0.0/8 ?ip4:4.0.0.0/8")
            .unwrap();
        assert_eq!(r.mechanisms[0].qualifier(), Qualifier::Pass);
        assert_eq!(r.mechanisms[1].qualifier(), Qualifier::Fail);
        assert_eq!(r.mechanisms[2].qualifier(), Qualifier::SoftFail);
        assert_eq!(r.mechanisms[3].qualifier(), Qualifier::Neutral);
    }

    #[test]
    fn test_no_vspf1_prefix() {
        assert!(parse_spf("spf1 ip4:1.2.3.4").is_err());
    }

    #[test]
    fn test_has_all_mechanism() {
        let r = parse_spf("v=spf1 include:x.com -all").unwrap();
        assert!(r.has_all_mechanism());

        let r = parse_spf("v=spf1 redirect=y.com").unwrap();
        assert!(!r.has_all_mechanism());
    }

    #[test]
    fn test_display_mechanism() {
        let r = parse_spf("v=spf1 include:_spf.google.com -all").unwrap();
        assert_eq!(format!("{}", r.mechanisms[0]), "include:_spf.google.com");
        assert_eq!(format!("{}", r.mechanisms[1]), "-all");
    }

    #[test]
    fn test_complex_real_world_spf() {
        let spf = "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ip4:203.0.113.0/24 mx a:mail.example.com/24 -all";
        let r = parse_spf(spf).unwrap();
        assert_eq!(r.mechanisms.len(), 6);
    }
}
