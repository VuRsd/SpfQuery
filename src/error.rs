use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum SpfError {
    #[error("DNS 查询失败 ({domain}): {message}")]
    DnsQueryFailed { domain: String, message: String },

    #[error("未找到 SPF 记录: {0}")]
    NoSpfRecord(String),

    #[error("域名 {0} 存在多条 SPF 记录（违反 RFC 7208 §4.5）")]
    MultipleSpfRecords(String),

    #[error("DNS 查询次数已达上限 ({count}/10)，域名: {domain}")]
    DnsLookupLimitExceeded { count: u32, domain: String },

    #[error("检测到循环引用: {}", chain.join(" → "))]
    CircularReference { chain: Vec<String> },

    #[error("SPF 记录格式错误 ({domain}): {reason}")]
    MalformedSpf { domain: String, reason: String },

    #[error("无效的 IP 地址: {0}")]
    InvalidIp(String),

    #[error("无效的 CIDR 表示: {0}")]
    InvalidCidr(String),

    #[error("{0}")]
    Other(String),
}

pub type SpfResult<T> = Result<T, SpfError>;
