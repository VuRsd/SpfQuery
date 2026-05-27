mod dns;
mod error;
mod matcher;
mod resolver;
mod spf;
mod tree;

use std::net::IpAddr;

use clap::Parser;
use owo_colors::OwoColorize;

use crate::dns::DnsClient;
use crate::resolver::SpfResolver;
use crate::tree::render_mx_tree;

#[derive(Parser, Debug)]
#[command(
    name = "spfquery",
    about = "SPF 记录递归查询工具 — 检查 IP 是否被 SPF 授权",
    version
)]
struct Cli {
    /// 要查询 SPF 的域名
    #[arg(short, long)]
    domain: String,

    /// 要检查的 IP 地址
    #[arg(short, long)]
    ip: String,

    /// 禁用彩色输出
    #[arg(long)]
    no_color: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // 检查 NO_COLOR 环境变量
    let use_color = !cli.no_color && std::env::var("NO_COLOR").is_err();

    // 解析 IP 地址
    let check_ip: IpAddr = match cli.ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("错误: 无效的 IP 地址: {}", cli.ip);
            std::process::exit(1);
        }
    };

    // 初始化 DNS 客户端
    let dns = match DnsClient::new() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("错误: {e}");
            std::process::exit(1);
        }
    };

    let domain = cli.domain.clone();

    // 打印标题
    print_header(&domain, check_ip, use_color);

    // 创建解析器并执行检查
    let resolver = SpfResolver::new(dns, check_ip, use_color);
    match resolver.check(&domain).await {
        Ok(result) => {
            // 打印 MX 记录
            if !result.mx_records.is_empty() {
                let mx_header = "MX Records:";
                if use_color {
                    println!(
                        "{}\n{}",
                        mx_header.bold(),
                        render_mx_tree(&result.mx_records, use_color)
                    );
                } else {
                    println!(
                        "{mx_header}\n{}",
                        render_mx_tree(&result.mx_records, use_color)
                    );
                }
            }

            // 打印 SPF 解析树
            let tree_header = "SPF Resolution Tree:";
            if use_color {
                println!("{}", tree_header.bold());
            } else {
                println!("{tree_header}");
            }
            println!("  {}", result.spf_tree.render(use_color));

            // 打印分隔线
            let sep = "━".repeat(50);
            if use_color {
                println!("{}", sep.dimmed());
            } else {
                println!("{sep}");
            }

            // 打印结果
            if result.matched {
                let result_text = format!("Result: ✓ IP {} is AUTHORIZED by SPF", result.check_ip);
                if use_color {
                    println!("{}", result_text.green().bold());
                } else {
                    println!("{result_text}");
                }
                if let Some(ref mech) = result.matched_mechanism {
                    let mech_text = format!("Matched mechanism: {mech}");
                    if use_color {
                        println!("{}", mech_text.green());
                    } else {
                        println!("{mech_text}");
                    }
                }
                if let Some(ref txt) = result.matched_txt {
                    let txt_text = format!("Matched TXT: {txt}");
                    if use_color {
                        println!("{}", txt_text.cyan());
                    } else {
                        println!("{txt_text}");
                    }
                }
            } else {
                let result_text =
                    format!("Result: ✗ IP {} is NOT authorized by SPF", result.check_ip);
                if use_color {
                    println!("{}", result_text.red().bold());
                } else {
                    println!("{result_text}");
                }
            }

            // DNS 查询次数
            let dns_text = format!("DNS Lookups: {}/10", result.dns_lookups);
            if result.dns_lookups >= 10 {
                if use_color {
                    println!("{}", dns_text.yellow());
                } else {
                    println!("{dns_text} ⚠");
                }
            } else if use_color {
                println!("{}", dns_text.dimmed());
            } else {
                println!("{dns_text}");
            }
        }
        Err(e) => {
            let sep = "━".repeat(50);
            if use_color {
                println!("{}", sep.dimmed());
            } else {
                println!("{sep}");
            }
            let error_text = format!("Error: {e}");
            if use_color {
                eprintln!("{}", error_text.red().bold());
            } else {
                eprintln!("{error_text}");
            }
            std::process::exit(1);
        }
    }
}

fn print_header(domain: &str, ip: IpAddr, use_color: bool) {
    let sep = "━".repeat(50);

    let title = "SPF Query Tool";
    if use_color {
        println!("{}", title.bold().underline());
    } else {
        println!("{title}");
        println!("{}", "=".repeat(title.len()));
    }

    let domain_label = format!("Domain:  {domain}");
    let ip_label = format!("Check IP: {ip}");

    if use_color {
        println!("{}", domain_label.cyan());
        println!("{}", ip_label.cyan());
        println!("{}", sep.dimmed());
    } else {
        println!("{domain_label}");
        println!("{ip_label}");
        println!("{sep}");
    }
    println!();
}
