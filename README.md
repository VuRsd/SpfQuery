# SpfQuery

SPF（Sender Policy Framework）记录递归查询 CLI 工具，用于检查指定 IP 地址是否被域名的 SPF 策略授权发送邮件。

## 功能特性

- **递归解析**：自动展开 `include`、`a`、`mx` 等间接引用机制，展示完整的 SPF 授权链路
- **树状可视化**：以彩色树形结构展示解析过程，直观显示 IP 匹配路径
- **精准匹配**：标记 IP 命中的具体机制和所在 TXT 记录
- **RFC 7208 合规**：
  - 10 次 DNS 查询上限检测（§4.6.1）
  - 循环引用检测（`include` 链）
  - 三态机制评估（Authorized / Denied / Skip）
  - 支持 `redirect=` / `exp=` 修饰符
- **多机制支持**：`all`、`include`、`a`、`mx`、`ip4`、`ip6`、`ptr`、`exists`
- **CIDR 支持**：完整的 IPv4/IPv6 CIDR 范围匹配
- **双输出模式**：彩色终端输出 / `--no-color` 纯文本模式

## 安装

### 从源码构建

需要 Rust 1.75+ 工具链：

```bash
git clone https://github.com/VuRsd/SpfQuery.git
cd SpfQuery
cargo build --release
```

编译产物位于 `target/release/spfquery`。

## 使用方法

```bash
spfquery --domain <域名> --ip <IP地址> [选项]
```

### 参数

| 参数 | 短格式 | 说明 | 必填 |
|------|--------|------|------|
| `--domain` | `-d` | 要查询 SPF 记录的域名 | 是 |
| `--ip` | `-i` | 要检查是否被授权的 IP 地址 | 是 |
| `--no-color` | — | 禁用彩色输出 | 否 |
| `--help` | `-h` | 显示帮助信息 | — |

### 示例

**检查 Google 的邮件服务器 IP 是否被 gmail.com 的 SPF 授权：**

```bash
spfquery -d gmail.com -i 74.125.0.1
```

**检查一个不在授权范围内的 IP：**

```bash
spfquery -d outlook.com -i 203.0.113.5
```

**纯文本输出（适合脚本处理或管道）：**

```bash
spfquery -d github.com -i 192.30.252.1 --no-color
```

## 输出示例

### 匹配成功

```
SPF Query Tool
==============
Domain:  outlook.com
Check IP: 40.92.0.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MX Records:
  └── outlook-com.olc.protection.outlook.com (priority: 5)
        └── 198.19.34.83

SPF Resolution Tree:
  outlook.com "v=spf1 include:spf2.outlook.com -all"
└── include:spf2.outlook.com (MATCHED!)
    └── spf2.outlook.com "v=spf1 ip4:40.92.0.0/16 ip4:52.103.0.0/17 ... -all"
        └── ip4:40.92.0.0/16 (MATCHED!)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Result: ✓ IP 40.92.0.1 is AUTHORIZED by SPF
Matched mechanism: include:spf2.outlook.com
Matched TXT: v=spf1 include:spf2.outlook.com -all
DNS Lookups: 2/10
```

### 匹配失败

```
SPF Resolution Tree:
  outlook.com "v=spf1 include:spf2.outlook.com -all"
├── include:spf2.outlook.com ✗
│   └── spf2.outlook.com "v=spf1 ip4:40.92.0.0/16 ... -all"
│       ├── ip4:40.92.0.0/16 ✗
│       ├── ip4:52.103.0.0/17 ✗
│       ├── ip6:2a01:111:f403:2800::/53 ✗
│       ├── ip6:2a01:111:f403:d000::/53 ✗
│       └── -all ✗
└── -all ✗

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Result: ✗ IP 203.0.113.5 is NOT authorized by SPF
DNS Lookups: 2/10
```

## 项目结构

```
SpfQuery/
├── Cargo.toml          # 项目配置与依赖
├── Cargo.lock          # 依赖锁定
└── src/
    ├── main.rs         # CLI 入口，参数解析，输出编排
    ├── dns.rs          # DNS 客户端（hickory-resolver 封装，查询计数）
    ├── spf.rs          # SPF 记录解析器（分词 → AST，14 个单元测试）
    ├── resolver.rs     # 递归解析引擎（三态评估，Box::pin 异步递归）
    ├── matcher.rs      # IP/CIDR 匹配（IPv4/IPv6，6 个单元测试）
    ├── tree.rs         # 树结构与 ANSI 彩色渲染器（3 个单元测试）
    └── error.rs        # 错误类型定义（8 种错误变体）
```

## 技术栈

| 依赖 | 用途 |
|------|------|
| [hickory-resolver](https://crates.io/crates/hickory-resolver) 0.26 | 异步 DNS 解析（TXT/MX/A/AAAA/PTR） |
| [hickory-proto](https://crates.io/crates/hickory-proto) 0.26 | DNS 记录类型枚举 |
| [tokio](https://crates.io/crates/tokio) | 异步运行时 |
| [clap](https://crates.io/crates/clap) 4 | CLI 参数解析（derive 宏） |
| [owo-colors](https://crates.io/crates/owo-colors) | 零分配终端 ANSI 颜色 |
| [ipnetwork](https://crates.io/crates/ipnetwork) | CIDR 解析与包含检查 |
| [thiserror](https://crates.io/crates/thiserror) | 结构化错误类型 |

## RFC 7208 合规细节

| 规则 | 实现 |
|------|------|
| `all` 机制 | qualifier 决定授权结果，`+all` 授权，`-all`/`~all`/`?all` 拒绝 |
| `include` 语义（§5.2） | 内部返回 Pass 时 include 条件匹配，外层 qualifier 决定最终结果；内部非 Pass 则跳过 |
| `redirect=` 修饰符（§6.1） | 仅当无 `all` 机制且无其他机制匹配时生效 |
| DNS 查询上限（§4.6.1） | 单次 SPF 检查最多 10 次需要 DNS 查询的机制，MX 展示查询不计入 |
| 循环引用 | `include` 链回溯检测，发现循环立即报错 |
| `ptr` 机制（§5.5） | 已实现但输出废弃警告 |
| FQDN 尾部点 | 自动去除 hickory 返回的尾部 `.` |
| 多 TXT 字符串拼接 | 自动拼接单条 TXT RR 中的多个字符串片段 |

## 许可证

MIT
