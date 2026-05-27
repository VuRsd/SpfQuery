use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use hickory_proto::rr::RData;
use hickory_resolver::TokioResolver;

use crate::error::{SpfError, SpfResult};

/// RFC 7208 §4.6.1: 单次 SPF 检查最多 10 次 DNS 查询（需要查表的机制）
const MAX_DNS_LOOKUPS: u32 = 10;

/// DNS 客户端，封装 hickory-resolver，带查询计数
pub struct DnsClient {
    resolver: TokioResolver,
    lookup_count: Arc<AtomicU32>,
}

impl DnsClient {
    pub fn new() -> SpfResult<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| SpfError::DnsQueryFailed {
                domain: String::new(),
                message: format!("初始化 DNS 解析器失败: {e}"),
            })?
            .build()
            .map_err(|e| SpfError::DnsQueryFailed {
                domain: String::new(),
                message: format!("构建 DNS 解析器失败: {e}"),
            })?;
        Ok(Self {
            resolver,
            lookup_count: Arc::new(AtomicU32::new(0)),
        })
    }

    pub fn lookup_count(&self) -> u32 {
        self.lookup_count.load(Ordering::SeqCst)
    }

    /// 增加查询计数，超限时报错
    fn count_lookup(&self, domain: &str) -> SpfResult<()> {
        let count = self.lookup_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count > MAX_DNS_LOOKUPS {
            Err(SpfError::DnsLookupLimitExceeded {
                count,
                domain: domain.to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// 查询 TXT 记录，返回所有 v=spf1 的 TXT 记录文本
    pub async fn txt_lookup(&self, domain: &str) -> SpfResult<Vec<String>> {
        self.count_lookup(domain)?;

        let response =
            self.resolver
                .txt_lookup(domain)
                .await
                .map_err(|e| SpfError::DnsQueryFailed {
                    domain: domain.to_string(),
                    message: e.to_string(),
                })?;

        let mut spf_records = Vec::new();
        for record in response.answers() {
            if let RData::TXT(txt) = &record.data {
                // txt_data 是 Vec<Vec<u8>>，拼接所有字符串片段
                let full_text: String = txt
                    .txt_data
                    .iter()
                    .map(|chunk| String::from_utf8_lossy(chunk))
                    .collect::<Vec<_>>()
                    .join("");

                if full_text.starts_with("v=spf1") {
                    spf_records.push(full_text);
                }
            }
        }

        Ok(spf_records)
    }

    /// 查询 MX 记录，返回 (preference, exchange) 列表
    pub async fn mx_lookup(&self, domain: &str) -> SpfResult<Vec<(u16, String)>> {
        self.count_lookup(domain)?;

        let response =
            self.resolver
                .mx_lookup(domain)
                .await
                .map_err(|e| SpfError::DnsQueryFailed {
                    domain: domain.to_string(),
                    message: e.to_string(),
                })?;

        let mut records: Vec<(u16, String)> = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let RData::MX(mx) = &record.data {
                    let exchange = strip_trailing_dot(mx.exchange.to_string());
                    Some((mx.preference, exchange))
                } else {
                    None
                }
            })
            .collect();

        records.sort_by_key(|(pref, _)| *pref);
        Ok(records)
    }

    /// 查询 MX 记录（不计入 SPF 查询次数限制，用于顶部展示）
    pub async fn mx_lookup_display(&self, domain: &str) -> Vec<(u16, String)> {
        match self.resolver.mx_lookup(domain).await {
            Ok(response) => {
                let mut records: Vec<(u16, String)> = response
                    .answers()
                    .iter()
                    .filter_map(|record| {
                        if let RData::MX(mx) = &record.data {
                            let exchange = strip_trailing_dot(mx.exchange.to_string());
                            Some((mx.preference, exchange))
                        } else {
                            None
                        }
                    })
                    .collect();
                records.sort_by_key(|(pref, _)| *pref);
                records
            }
            Err(_) => Vec::new(),
        }
    }

    /// 查询 A + AAAA 记录，返回 IP 列表（计入查询次数）
    pub async fn ip_lookup(&self, domain: &str) -> SpfResult<Vec<IpAddr>> {
        self.count_lookup(domain)?;
        self.ip_lookup_inner(domain).await
    }

    /// 查询 A + AAAA 记录（不计入查询次数，用于 MX 展示等辅助查询）
    pub async fn ip_lookup_no_count(&self, domain: &str) -> SpfResult<Vec<IpAddr>> {
        self.ip_lookup_inner(domain).await
    }

    /// 内部 IP 查询（不计入查询次数）
    async fn ip_lookup_inner(&self, domain: &str) -> SpfResult<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 尝试 A 记录
        if let Ok(response) = self.resolver.ipv4_lookup(domain).await {
            for record in response.answers() {
                if let RData::A(addr) = &record.data {
                    ips.push(IpAddr::V4(addr.0));
                }
            }
        }

        // 尝试 AAAA 记录
        if let Ok(response) = self.resolver.ipv6_lookup(domain).await {
            for record in response.answers() {
                if let RData::AAAA(addr) = &record.data {
                    ips.push(IpAddr::V6(addr.0));
                }
            }
        }

        Ok(ips)
    }

    /// 查询 PTR 记录（反向 DNS）
    pub async fn ptr_lookup(&self, ip: IpAddr) -> SpfResult<Vec<String>> {
        self.count_lookup(&ip.to_string())?;

        let response =
            self.resolver
                .reverse_lookup(ip)
                .await
                .map_err(|e| SpfError::DnsQueryFailed {
                    domain: ip.to_string(),
                    message: e.to_string(),
                })?;

        let names: Vec<String> = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let RData::PTR(ptr) = &record.data {
                    Some(strip_trailing_dot(ptr.0.to_string()))
                } else {
                    None
                }
            })
            .collect();

        Ok(names)
    }
}

/// 去掉 FQDN 尾部的点（hickory 返回的域名带尾部点）
fn strip_trailing_dot(s: String) -> String {
    if s.ends_with('.') {
        s[..s.len() - 1].to_string()
    } else {
        s
    }
}
