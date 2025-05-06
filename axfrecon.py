#!/usr/bin/env python3

import click
import dns.resolver
import dns.zone
import dns.query
import tqdm
import os
from typing import Set, List
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_dns_records(domain: str, record_type: str) -> List[str]:
    """获取指定域名的DNS记录"""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        if record_type == 'NS':
            return [str(rdata.target).rstrip('.') for rdata in answers]
        elif record_type == 'CNAME':
            return [str(rdata.target).rstrip('.') for rdata in answers]
        else:
            return [str(rdata) for rdata in answers]
    except Exception as e:
        return []

def get_nameservers(domain: str) -> List[str]:
    """获取域名的NS记录"""
    return get_dns_records(domain, 'NS')

def collect_subdomains_from_dns(domain: str, subdomains: Set[str]) -> None:
    """通过查询不同类型的DNS记录来收集子域名"""
    common_prefixes = ['www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'ns4',
                      'blog', 'dev', 'test', 'admin', 'api', 'stage', 'git', 'docs',
                      'web', 'cdn', 'static', 'app', 'portal', 'vpn', 'mx', 'support']
    
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {}
        
        # 检查常见子域名
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            for record_type in record_types:
                future = executor.submit(get_dns_records, subdomain, record_type)
                future_to_subdomain[future] = subdomain
        
        # 收集结果
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                records = future.result()
                if records:
                    subdomains.add(subdomain)
                    # 对CNAME记录进行递归查询
                    if 'CNAME' in record_types:
                        cname_records = get_dns_records(subdomain, 'CNAME')
                        for cname in cname_records:
                            if domain in cname:
                                subdomains.add(cname)
            except Exception as e:
                pass

def test_zone_transfer(domain, nameserver):
    """测试指定域名在指定DNS服务器上是否存在域传送漏洞"""
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
        return True, zone
    except Exception as e:
        return False, None

@click.command()
@click.argument('domain', required=False)
@click.option('-f', '--file', help='从文本文件读取域名列表（每行一个域名）')
@click.option('-s', '--scan-subdomains', is_flag=True, default=True, help='是否开启子域名扫描（默认开启）')
@click.option('-o', '--output', default='results.txt', help='指定输出文件路径（默认为results.txt）')
def main(domain, file, scan_subdomains, output):
    """DNS域传送漏洞检测工具"""
    domains = []
    
    # 从文件读取域名或使用命令行参数
    if file:
        try:
            with open(file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            if not domains:
                click.echo("[!] 文件中未找到有效域名")
                return
            # 从文件读取域名时默认关闭子域名扫描
            scan_subdomains = False
        except Exception as e:
            click.echo(f"[!] 读取文件失败: {str(e)}")
            return
    elif domain:
        domains = [domain]
    else:
        click.echo("[!] 请提供域名或域名列表文件")
        return
    
    for domain in domains:
        click.echo(f"\n[*] 开始检测域名: {domain}")
        
        # 获取域名的NS记录
        click.echo("\n[*] 正在获取NS记录...")
        nameservers = get_nameservers(domain)
        
        if not nameservers:
            click.echo(f"[!] 未找到域名 {domain} 的NS记录")
            continue
    
        click.echo(f"[+] 发现 {len(nameservers)} 个DNS服务器")
        
        # 检测结果
        vulnerable_servers = []
        subdomains = set()
        
        if scan_subdomains:
            # 第一步：通过DNS记录收集子域名
            click.echo("\n[*] 正在通过DNS记录收集子域名...")
            collect_subdomains_from_dns(domain, subdomains)
            if subdomains:
                click.echo(f"\n[+] 通过DNS记录收集到 {len(subdomains)} 个子域名")
            
            # 第二步：尝试通过域传送收集子域名
            click.echo("\n[*] 正在尝试通过域传送收集子域名...")
            with tqdm.tqdm(nameservers, desc="收集进度") as pbar:
                for ns in pbar:
                    pbar.set_description(f"正在从 {ns} 收集")
                    _, zone = test_zone_transfer(domain, ns)
                    if zone:
                        for name, _ in zone.nodes.items():
                            subdomain = str(name) + '.' + domain
                            if subdomain.startswith('@'):
                                subdomain = domain
                            subdomains.add(subdomain)
            
            if len(subdomains) > 0:
                click.echo(f"\n[+] 总共收集到 {len(subdomains)} 个子域名")
        
        # 第二步：对所有域名进行漏洞检测
        all_domains = list(subdomains) if subdomains else [domain]
        click.echo("\n[*] 开始进行DNS域传送漏洞检测...")
        
        with tqdm.tqdm(all_domains, desc="检测进度") as pbar:
            for test_domain in pbar:
                pbar.set_description(f"正在检测 {test_domain}")
                domain_ns = get_nameservers(test_domain)
                if domain_ns:
                    for ns in domain_ns:
                        is_vulnerable, _ = test_zone_transfer(test_domain, ns)
                        if is_vulnerable:
                            vulnerable_servers.append({"domain": test_domain, "nameserver": ns})
        
        # 输出结果
        click.echo("\n[*] 检测完成")
        
        # 保存结果到文件
        with open(output, 'a+') as f:
            f.write(f"域名: {domain}\n")
            
            # 输出子域名收集结果
            f.write("\n[收集到的子域名]\n")
            if subdomains:
                for subdomain in sorted(subdomains):
                    f.write(f"{subdomain}\n")
            else:
                f.write("未收集到子域名\n")
            
            # 输出漏洞检测结果
            f.write("\n[漏洞检测结果]\n")
            if vulnerable_servers:
                for result in vulnerable_servers:
                    f.write(f"域名: {result['domain']}\n")
                    f.write(f"存在漏洞的DNS服务器: {result['nameserver']}\n\n")
            else:
                f.write("未发现存在域传送漏洞的DNS服务器\n")
            f.write("-" * 30 + "\n")
        
        # 输出到控制台
        if vulnerable_servers:
            click.echo("\n[!] 发现存在漏洞的DNS服务器:")
            for result in vulnerable_servers:
                click.echo(f"    - {result['domain']} -> {result['nameserver']}")
        else:
            click.echo("\n[+] 未发现存在域传送漏洞的DNS服务器")
    
    click.echo(f"\n[+] 结果已保存到: {output}")

if __name__ == '__main__':
    main()