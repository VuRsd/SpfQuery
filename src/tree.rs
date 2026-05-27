#![allow(dead_code)]

use std::fmt::Write as FmtWrite;

use owo_colors::OwoColorize;

/// 树节点状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Match,
    NoMatch,
    Warning,
    Info,
    Error,
}

/// 解析树节点
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub label: String,
    pub detail: Option<String>,
    pub status: NodeStatus,
    pub children: Vec<TreeNode>,
    pub is_match_point: bool,
}

impl TreeNode {
    pub fn new(label: impl Into<String>, status: NodeStatus) -> Self {
        Self {
            label: label.into(),
            detail: None,
            status,
            children: Vec::new(),
            is_match_point: false,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_children(mut self, children: Vec<TreeNode>) -> Self {
        self.children = children;
        self
    }

    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }

    pub fn set_match_point(&mut self) {
        self.is_match_point = true;
        self.status = NodeStatus::Match;
    }

    /// 渲染树为带 ANSI 颜色的字符串
    pub fn render(&self, use_color: bool) -> String {
        let mut output = String::new();
        self.render_node(&mut output, "", true, true, use_color);
        output
    }

    fn render_node(
        &self,
        output: &mut String,
        prefix: &str,
        is_last: bool,
        is_root: bool,
        use_color: bool,
    ) {
        // 连接符
        let connector = if is_root {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };

        // 渲染标签
        let label_colored = self.colorize(&self.label, use_color);
        let _ = write!(output, "{prefix}{connector}{label_colored}");

        // 渲染 detail
        if let Some(ref detail) = self.detail {
            let detail_colored = if use_color {
                format!(" \"{}\"", detail).cyan().dimmed().to_string()
            } else {
                format!(" \"{}\"", detail)
            };
            let _ = write!(output, "{detail_colored}");
        }

        // 渲染匹配状态
        let status_str = self.status_suffix(use_color);
        let _ = write!(output, "{status_str}");

        // 匹配点标记
        if self.is_match_point {
            let matched = if use_color {
                " (MATCHED!)".green().bold().underline().to_string()
            } else {
                " (MATCHED!)".to_string()
            };
            let _ = write!(output, "{matched}");
        }

        let _ = writeln!(output);

        // 子节点前缀
        let child_prefix = if is_root {
            prefix.to_string()
        } else if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };

        let child_count = self.children.len();
        for (i, child) in self.children.iter().enumerate() {
            child.render_node(
                output,
                &child_prefix,
                i == child_count - 1,
                false,
                use_color,
            );
        }
    }

    fn status_suffix(&self, use_color: bool) -> String {
        if self.is_match_point {
            return String::new(); // 匹配点用 (MATCHED!) 代替
        }

        match self.status {
            NodeStatus::Match => {
                if use_color {
                    format!(" {}", "✓".green())
                } else {
                    " ✓".to_string()
                }
            }
            NodeStatus::NoMatch => {
                if use_color {
                    format!(" {}", "✗".red())
                } else {
                    " ✗".to_string()
                }
            }
            NodeStatus::Warning => {
                if use_color {
                    format!(" {}", "⚠".yellow())
                } else {
                    " ⚠".to_string()
                }
            }
            NodeStatus::Info => String::new(),
            NodeStatus::Error => {
                if use_color {
                    format!(" {}", "✗".red())
                } else {
                    " ✗".to_string()
                }
            }
        }
    }

    fn colorize(&self, text: &str, use_color: bool) -> String {
        if !use_color {
            return text.to_string();
        }

        match self.status {
            NodeStatus::Match => text.green().to_string(),
            NodeStatus::NoMatch => text.red().to_string(),
            NodeStatus::Warning => text.yellow().to_string(),
            NodeStatus::Info => text.cyan().to_string(),
            NodeStatus::Error => text.red().bold().to_string(),
        }
    }
}

/// 渲染 MX 记录树（信息性展示，不计入 DNS 限制）
pub fn render_mx_tree(
    mx_records: &[(u16, String, Vec<std::net::IpAddr>)],
    use_color: bool,
) -> String {
    let mut output = String::new();
    for (i, (pref, exchange, ips)) in mx_records.iter().enumerate() {
        let is_last = i == mx_records.len() - 1;
        let connector = if is_last { "└── " } else { "├── " };

        let label = format!("{exchange} (priority: {pref})");
        let label_colored = if use_color {
            label.cyan().to_string()
        } else {
            label
        };
        let _ = writeln!(output, "  {connector}{label_colored}");

        let ip_prefix = if is_last { "      " } else { "  │   " };
        for (j, ip) in ips.iter().enumerate() {
            let ip_is_last = j == ips.len() - 1;
            let ip_connector = if ip_is_last {
                "└── "
            } else {
                "├── "
            };
            let ip_str = ip.to_string();
            let ip_colored = if use_color {
                ip_str.dimmed().to_string()
            } else {
                ip_str
            };
            let _ = writeln!(output, "  {ip_prefix}{ip_connector}{ip_colored}");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_tree_render() {
        let root = TreeNode::new("example.com", NodeStatus::Info)
            .with_detail("v=spf1 ip4:1.2.3.0/24 -all")
            .with_children(vec![
                TreeNode::new("ip4:1.2.3.0/24", NodeStatus::NoMatch),
                {
                    let mut node = TreeNode::new("ip4:10.0.0.0/8", NodeStatus::Match);
                    node.set_match_point();
                    node
                },
                TreeNode::new("-all", NodeStatus::NoMatch),
            ]);

        let output = root.render(false);
        assert!(output.contains("example.com"));
        assert!(output.contains("ip4:1.2.3.0/24"));
        assert!(output.contains("MATCHED!"));
        assert!(output.contains("├──"));
        assert!(output.contains("└──"));
    }

    #[test]
    fn test_nested_tree_render() {
        let root = TreeNode::new("example.com", NodeStatus::Info).with_children(vec![
            TreeNode::new("include:_spf.google.com", NodeStatus::Info).with_children(vec![
                TreeNode::new("_spf.google.com", NodeStatus::Info)
                    .with_detail("v=spf1 ip4:35.190.247.0/24 -all")
                    .with_children(vec![
                        TreeNode::new("ip4:35.190.247.0/24", NodeStatus::NoMatch),
                        TreeNode::new("-all", NodeStatus::NoMatch),
                    ]),
            ]),
        ]);

        let output = root.render(false);
        assert!(output.contains("include:_spf.google.com"));
        assert!(output.contains("_spf.google.com"));
    }

    #[test]
    fn test_colored_render_no_panic() {
        let root = TreeNode::new("test", NodeStatus::Match).with_children(vec![
            TreeNode::new("child1", NodeStatus::NoMatch),
            TreeNode::new("child2", NodeStatus::Warning),
        ]);
        let _output = root.render(true);
    }
}
