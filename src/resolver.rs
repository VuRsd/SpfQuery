use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use crate::dns::DnsClient;
use crate::error::{SpfError, SpfResult};
use crate::matcher::ip_in_resolved_ips;
use crate::spf::{self, Mechanism, Modifier, Qualifier};
use crate::tree::{NodeStatus, TreeNode};

/// 机制评估的三态结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MechEval {
    /// 机制条件匹配，qualifier 为 Pass → IP 被授权
    Authorized,
    /// 机制条件匹配，但 qualifier 不是 Pass（Fail/SoftFail/Neutral）→ 最终结果，不再继续
    Denied,
    /// 机制条件不匹配 → 继续下一条机制
    Skip,
}

impl MechEval {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Authorized | Self::Denied)
    }

    fn is_authorized(self) -> bool {
        self == Self::Authorized
    }
}

/// SPF 检查结果
#[allow(dead_code)]
pub struct SpfCheckResult {
    pub domain: String,
    pub check_ip: IpAddr,
    pub mx_records: Vec<(u16, String, Vec<IpAddr>)>,
    pub spf_tree: TreeNode,
    pub matched: bool,
    pub matched_mechanism: Option<String>,
    pub matched_txt: Option<String>,
    pub dns_lookups: u32,
}

/// SPF 递归解析器
pub struct SpfResolver {
    dns: DnsClient,
    check_ip: IpAddr,
    #[allow(dead_code)]
    use_color: bool,
}

impl SpfResolver {
    pub fn new(dns: DnsClient, check_ip: IpAddr, use_color: bool) -> Self {
        Self {
            dns,
            check_ip,
            use_color,
        }
    }

    /// 执行完整的 SPF 检查
    pub async fn check(&self, domain: &str) -> SpfResult<SpfCheckResult> {
        let domain = domain.to_lowercase();

        // 1. 查询 MX 记录（信息性展示，不计入 SPF 查询限制）
        let mx_raw = self.dns.mx_lookup_display(&domain).await;
        let mut mx_records = Vec::new();
        for (pref, exchange) in &mx_raw {
            let ips = self
                .dns
                .ip_lookup_no_count(exchange)
                .await
                .unwrap_or_default();
            mx_records.push((*pref, exchange.clone(), ips));
        }

        // 2. 递归解析 SPF
        let mut visited = HashSet::new();
        let (spf_tree, matched, matched_mechanism, matched_txt) =
            self.resolve_spf(&domain, 0, &mut visited).await?;

        Ok(SpfCheckResult {
            domain,
            check_ip: self.check_ip,
            mx_records,
            spf_tree,
            matched,
            matched_mechanism,
            matched_txt,
            dns_lookups: self.dns.lookup_count(),
        })
    }

    /// 递归解析 SPF 记录（使用 Box::pin 处理递归异步）
    /// 返回 (TreeNode, 是否授权, 匹配的机制文本, 匹配的 TXT 记录)
    fn resolve_spf<'a>(
        &'a self,
        domain: &'a str,
        depth: usize,
        visited: &'a mut HashSet<String>,
    ) -> Pin<
        Box<dyn Future<Output = SpfResult<(TreeNode, bool, Option<String>, Option<String>)>> + 'a>,
    > {
        Box::pin(async move {
            // 循环引用检测
            if visited.contains(domain) {
                let chain: Vec<String> = visited.iter().cloned().collect();
                return Err(SpfError::CircularReference { chain });
            }
            visited.insert(domain.to_string());

            // 查询 TXT 记录
            let spf_texts = self.dns.txt_lookup(domain).await?;

            if spf_texts.is_empty() {
                return Err(SpfError::NoSpfRecord(domain.to_string()));
            }
            if spf_texts.len() > 1 {
                return Err(SpfError::MultipleSpfRecords(domain.to_string()));
            }

            let spf_text = &spf_texts[0];
            let record = spf::parse_spf(spf_text).map_err(|e| SpfError::MalformedSpf {
                domain: domain.to_string(),
                reason: e.to_string(),
            })?;

            // 创建根节点
            let mut root = TreeNode::new(domain, NodeStatus::Info).with_detail(spf_text.clone());

            let mut final_authorized: Option<bool> = None;
            let mut matched_mechanism: Option<String> = None;
            let mut matched_txt: Option<String> = None;

            // 遍历所有机制，遇到第一个"匹配"的机制即停止
            for mechanism in &record.mechanisms {
                let (child, eval) = self
                    .evaluate_mechanism(mechanism, domain, depth, visited)
                    .await?;

                root.add_child(child);

                if eval.is_terminal() && final_authorized.is_none() {
                    final_authorized = Some(eval.is_authorized());
                    matched_mechanism = Some(format!("{mechanism}"));
                    matched_txt = Some(spf_text.clone());
                }

                if eval.is_terminal() {
                    break;
                }
            }

            // redirect 处理：仅当无机制匹配且无 all 机制时
            if final_authorized.is_none() && !record.has_all_mechanism() {
                if let Some(redirect_domain) = record.redirect_domain() {
                    let (redirect_tree, r_auth, r_mech, r_txt) = self
                        .resolve_spf(redirect_domain, depth + 1, visited)
                        .await?;

                    let mut redirect_node = TreeNode::new(
                        format!("redirect={redirect_domain}"),
                        if r_auth {
                            NodeStatus::Match
                        } else {
                            NodeStatus::NoMatch
                        },
                    );
                    redirect_node.add_child(redirect_tree);

                    final_authorized = Some(r_auth);
                    matched_mechanism = r_mech;
                    matched_txt = r_txt;

                    root.add_child(redirect_node);
                }
            }

            // exp 处理：仅记录
            for modifier in &record.modifiers {
                if let Modifier::Exp { domain: exp_domain } = modifier {
                    let exp_node = TreeNode::new(format!("exp={exp_domain}"), NodeStatus::Info)
                        .with_detail("解释域名（不影响 SPF 结果）");
                    root.add_child(exp_node);
                }
            }

            // 回溯
            visited.remove(domain);

            let authorized = final_authorized.unwrap_or(false);
            Ok((root, authorized, matched_mechanism, matched_txt))
        })
    }

    /// 评估单个机制，返回 (TreeNode, MechEval)
    async fn evaluate_mechanism(
        &self,
        mechanism: &Mechanism,
        current_domain: &str,
        depth: usize,
        visited: &mut HashSet<String>,
    ) -> SpfResult<(TreeNode, MechEval)> {
        match mechanism {
            Mechanism::All { qualifier } => {
                // all 始终匹配任何 IP，qualifier 决定结果
                let authorized = *qualifier == Qualifier::Pass;
                let eval = if authorized {
                    MechEval::Authorized
                } else {
                    MechEval::Denied
                };

                let mut node = TreeNode::new(
                    format!("{mechanism}"),
                    if authorized {
                        NodeStatus::Match
                    } else {
                        NodeStatus::NoMatch
                    },
                );
                if authorized {
                    node.set_match_point();
                }
                Ok((node, eval))
            }

            Mechanism::Ip4 { qualifier, network } => {
                let in_range = match self.check_ip {
                    IpAddr::V4(ip4) => network.contains(ip4),
                    IpAddr::V6(_) => false,
                };
                let eval = if in_range {
                    if *qualifier == Qualifier::Pass {
                        MechEval::Authorized
                    } else {
                        MechEval::Denied
                    }
                } else {
                    MechEval::Skip
                };

                let mut node = TreeNode::new(
                    format!("{mechanism}"),
                    match eval {
                        MechEval::Authorized => NodeStatus::Match,
                        MechEval::Denied => NodeStatus::NoMatch,
                        MechEval::Skip => NodeStatus::NoMatch,
                    },
                );
                if eval.is_authorized() {
                    node.set_match_point();
                }
                Ok((node, eval))
            }

            Mechanism::Ip6 { qualifier, network } => {
                let in_range = match self.check_ip {
                    IpAddr::V6(ip6) => network.contains(ip6),
                    IpAddr::V4(_) => false,
                };
                let eval = if in_range {
                    if *qualifier == Qualifier::Pass {
                        MechEval::Authorized
                    } else {
                        MechEval::Denied
                    }
                } else {
                    MechEval::Skip
                };

                let mut node = TreeNode::new(
                    format!("{mechanism}"),
                    match eval {
                        MechEval::Authorized => NodeStatus::Match,
                        _ => NodeStatus::NoMatch,
                    },
                );
                if eval.is_authorized() {
                    node.set_match_point();
                }
                Ok((node, eval))
            }

            Mechanism::A {
                qualifier,
                domain,
                cidr4,
                cidr6,
            } => {
                let target_domain = domain.as_deref().unwrap_or(current_domain);
                let ips = match self.dns.ip_lookup(target_domain).await {
                    Ok(ips) => ips,
                    Err(_) => Vec::new(),
                };

                let in_range = ip_in_resolved_ips(self.check_ip, &ips, *cidr4, *cidr6);
                let eval = if in_range {
                    if *qualifier == Qualifier::Pass {
                        MechEval::Authorized
                    } else {
                        MechEval::Denied
                    }
                } else {
                    MechEval::Skip
                };

                let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                let detail = if ip_list.is_empty() {
                    "无 A/AAAA 记录".to_string()
                } else {
                    ip_list.join(", ")
                };

                let mut node = TreeNode::new(
                    format!("{mechanism}"),
                    match eval {
                        MechEval::Authorized => NodeStatus::Match,
                        _ => NodeStatus::NoMatch,
                    },
                )
                .with_detail(detail);

                if eval.is_authorized() {
                    node.set_match_point();
                }
                Ok((node, eval))
            }

            Mechanism::Mx {
                qualifier,
                domain,
                cidr4,
                cidr6,
            } => {
                let target_domain = domain.as_deref().unwrap_or(current_domain);
                let mx_records = match self.dns.mx_lookup(target_domain).await {
                    Ok(records) => records,
                    Err(_) => Vec::new(),
                };

                let mut mx_node = TreeNode::new(format!("{mechanism}"), NodeStatus::Info);

                let mut any_in_range = false;

                for (_pref, exchange) in &mx_records {
                    let ips = match self.dns.ip_lookup(exchange).await {
                        Ok(ips) => ips,
                        Err(_) => Vec::new(),
                    };

                    let in_range = ip_in_resolved_ips(self.check_ip, &ips, *cidr4, *cidr6);
                    let child_authorized = in_range && *qualifier == Qualifier::Pass;

                    if in_range && !any_in_range {
                        any_in_range = true;
                    }

                    let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                    let detail = if ip_list.is_empty() {
                        "无 A/AAAA 记录".to_string()
                    } else {
                        ip_list.join(", ")
                    };

                    let mx_child = TreeNode::new(
                        exchange.as_str(),
                        if child_authorized {
                            NodeStatus::Match
                        } else {
                            NodeStatus::NoMatch
                        },
                    )
                    .with_detail(detail);

                    mx_node.add_child(mx_child);
                }

                let eval = if any_in_range {
                    if *qualifier == Qualifier::Pass {
                        MechEval::Authorized
                    } else {
                        MechEval::Denied
                    }
                } else {
                    MechEval::Skip
                };

                if eval.is_authorized() {
                    mx_node.status = NodeStatus::Match;
                    mx_node.set_match_point();
                } else if mx_records.is_empty() {
                    mx_node.status = NodeStatus::Warning;
                    mx_node.detail = Some("无 MX 记录".to_string());
                } else {
                    mx_node.status = NodeStatus::NoMatch;
                }

                Ok((mx_node, eval))
            }

            Mechanism::Include { qualifier, domain } => {
                let mut include_node = TreeNode::new(format!("{mechanism}"), NodeStatus::Info);

                match self.resolve_spf(domain, depth + 1, visited).await {
                    Ok((inner_tree, inner_authorized, _inner_mech, _inner_txt)) => {
                        // RFC 7208 §5.2: include 只在内部返回 Pass 时匹配
                        // 内部 Pass → include 条件匹配，外层 qualifier 决定结果
                        // 内部非 Pass → include 条件不匹配，继续下一条机制
                        let eval = if inner_authorized {
                            // 内部返回 Pass
                            if *qualifier == Qualifier::Pass {
                                MechEval::Authorized
                            } else {
                                MechEval::Denied
                            }
                        } else {
                            // 内部未返回 Pass → include 不匹配
                            MechEval::Skip
                        };

                        include_node.status = match eval {
                            MechEval::Authorized => NodeStatus::Match,
                            MechEval::Denied => NodeStatus::NoMatch,
                            MechEval::Skip => NodeStatus::NoMatch,
                        };

                        if eval.is_authorized() {
                            include_node.set_match_point();
                        }

                        include_node.add_child(inner_tree);
                        Ok((include_node, eval))
                    }
                    Err(e) => {
                        include_node.status = NodeStatus::Error;
                        include_node.detail = Some(format!("错误: {e}"));
                        // DNS 错误 → include 条件不匹配
                        Ok((include_node, MechEval::Skip))
                    }
                }
            }

            Mechanism::Ptr { qualifier, domain } => {
                let target_domain = domain.as_deref().unwrap_or(current_domain);

                let mut node = TreeNode::new(format!("{mechanism}"), NodeStatus::Warning);
                node.detail = Some("⚠ ptr 机制已废弃 (RFC 7208 §5.5)".to_string());

                match self.dns.ptr_lookup(self.check_ip).await {
                    Ok(ptr_names) => {
                        let mut in_range = false;
                        for ptr_name in &ptr_names {
                            if ptr_name.ends_with(target_domain) || ptr_name == target_domain {
                                if let Ok(ips) = self.dns.ip_lookup(ptr_name).await {
                                    if ips.contains(&self.check_ip) {
                                        in_range = true;
                                        break;
                                    }
                                }
                            }
                        }

                        let eval = if in_range {
                            if *qualifier == Qualifier::Pass {
                                MechEval::Authorized
                            } else {
                                MechEval::Denied
                            }
                        } else {
                            MechEval::Skip
                        };

                        node.status = match eval {
                            MechEval::Authorized => NodeStatus::Match,
                            _ => NodeStatus::NoMatch,
                        };
                        if eval.is_authorized() {
                            node.set_match_point();
                        }
                        Ok((node, eval))
                    }
                    Err(_) => {
                        node.status = NodeStatus::NoMatch;
                        Ok((node, MechEval::Skip))
                    }
                }
            }

            Mechanism::Exists { qualifier, domain } => {
                let exists = match self.dns.ip_lookup(domain).await {
                    Ok(ips) => !ips.is_empty(),
                    Err(_) => false,
                };

                let eval = if exists {
                    if *qualifier == Qualifier::Pass {
                        MechEval::Authorized
                    } else {
                        MechEval::Denied
                    }
                } else {
                    MechEval::Skip
                };

                let mut node = TreeNode::new(
                    format!("{mechanism}"),
                    match eval {
                        MechEval::Authorized => NodeStatus::Match,
                        _ => NodeStatus::NoMatch,
                    },
                );

                if eval.is_authorized() {
                    node.set_match_point();
                }

                Ok((node, eval))
            }
        }
    }
}
