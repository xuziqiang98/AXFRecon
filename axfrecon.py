#!/usr/bin/env python3

import click
import dns.resolver
import dns.zone
import dns.query
import tqdm
import os
import traceback
import subprocess
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

def get_nameservers(domain: str) -> list:
    """
    查询指定域名的NS记录，返回所有域名服务器列表。

    参数:
        domain (str): 要查询的域名。

    返回:
        list: 包含所有域名服务器的列表。

    异常:
        Exception: 当dig命令执行失败或未找到时抛出。
    """
    cmd = ['dig', '+short', 'NS', domain]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        raise Exception(f"dig命令执行失败，退出码 {e.returncode}：{e.stderr}") from e
    except FileNotFoundError as e:
        raise Exception("未找到'dig'命令，请确保已安装dnsutils（如bind-utils）包。") from e

    # 处理输出，提取非空行并去除首尾空格
    # 去除末尾的.
    ns_list = [line.strip().rstrip('.') for line in result.stdout.splitlines() if line.strip()]
    return ns_list

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

def test_zone_transfer(domain: str, nameserver: str) -> bool:
    """
    检测指定域名服务器是否允许区域传输（AXFR）。
    
    参数:
        domain (str): 要检测的域名。
        nameserver (str): 目标域名服务器的地址。
    
    返回:
        bool: 若输出包含 "Transfer failed" 返回 False，否则返回 True。
    
    异常:
        RuntimeError: 当系统未安装 `dig` 命令时抛出。
    """
    cmd = ["dig", f"@{nameserver}", "axfr", domain]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError("未找到 'dig' 命令，请确保已安装 dnsutils 或 bind-utils 包。") from e
    
    # 合并标准输出和错误输出，统一检查
    output = result.stdout + result.stderr
    failed_features = ["Transfer failed", 
                       "timed out", 
                       "network unreachable", 
                       "host unreachable", 
                       "not found", 
                       "connection refused"]
    for feature in failed_features:
        if feature in result.stdout or feature in result.stderr:
            return False
    return True

@click.command()
@click.argument('domain', required=False)
@click.option('-f', '--file', help='从文本文件读取域名列表（每行一个域名）')
@click.option('-s', '--scan-subdomains', default=True, help='是否开启子域名扫描（默认开启）')
@click.option('-o', '--output', default='results.txt', help='指定输出文件路径（默认为results.txt）')
def main(domain, file, scan_subdomains, output):
    """DNS域传送漏洞检测工具"""
    domains = []
    
    def normalize_domain(domain: str) -> str:
        """规范化域名，移除http://、https://和www.前缀"""
        # 移除http://和https://前缀
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        
        # 移除可能存在的www.前缀
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # 移除可能存在的路径和参数
        domain = domain.split('/')[0]
        
        return domain

    # 从文件读取域名或使用命令行参数
    if file:
        try:
            with open(file, 'r') as f:
                domains = [normalize_domain(line.strip()) for line in f if line.strip()]
            if not domains:
                click.echo("[!] 文件中未找到有效域名")
                # 创建一个空结果文件
                try:
                    with open(output, 'w') as f:
                        f.write("[!] 文件中未找到有效域名\n")
                    click.echo(f"[+] 结果已保存到: {output}")
                except Exception as e:
                    click.echo(f"[!] 无法创建输出文件: {str(e)}")
                return
        except Exception as e:
            click.echo(f"[!] 读取文件失败: {str(e)}")
            # 创建一个错误报告文件
            try:
                with open(output, 'w') as f:
                    f.write(f"[!] 读取文件失败: {str(e)}\n")
                click.echo(f"[+] 结果已保存到: {output}")
            except Exception as e:
                click.echo(f"[!] 无法创建输出文件: {str(e)}")
            return
    elif domain:
        domains = [normalize_domain(domain)]
    else:
        click.echo("[!] 请提供域名或域名列表文件")
        # 创建一个错误报告文件
        try:
            with open(output, 'w') as f:
                f.write("[!] 未提供域名或域名列表文件\n")
            click.echo(f"[+] 结果已保存到: {output}")
        except Exception as e:
            click.echo(f"[!] 无法创建输出文件: {str(e)}")
        return
    
    # 初始化结果文件（如果需要）
    try:
        # 如果文件不存在，创建一个新文件
        if not os.path.exists(output):
            with open(output, 'w') as f:
                f.write("# DNS域传送漏洞检测结果\n\n")
    except Exception as e:
        click.echo(f"[!] 无法初始化输出文件: {str(e)}")
        return
    
    for domain in domains:
        click.echo(f"\n[*] 开始检测域名: {domain}")
        
        # 获取域名的NS记录
        click.echo("\n[*] 正在获取NS记录...")
        try:
            nameservers = get_nameservers(domain)
        except Exception as e:
            click.echo(f"[!] 获取NS记录失败: {str(e)}")
            # 记录错误到文件
            try:
                with open(output, 'a+') as f:
                    f.write(f"域名: {domain}\n")
                    f.write(f"[!] 获取NS记录失败: {str(e)}\n")
                    f.write("-" * 30 + "\n")
            except Exception as write_err:
                click.echo(f"[!] 保存结果到文件失败: {str(write_err)}")
            continue
        
        if not nameservers:
            click.echo(f"[!] 未找到域名 {domain} 的NS记录")
            # 记录到文件
            try:
                with open(output, 'a+') as f:
                    f.write(f"域名: {domain}\n")
                    f.write("[!] 未找到NS记录\n")
                    f.write("-" * 30 + "\n")
            except Exception as write_err:
                click.echo(f"[!] 保存结果到文件失败: {str(write_err)}")
            continue
    
        click.echo(f"[+] 发现 {len(nameservers)} 个DNS服务器")
        
        # 检测结果
        vulnerable_servers = []
        subdomains = set()
        
        if scan_subdomains:
            click.echo("\n[*] 正在通过DNS记录收集子域名...")
            collect_subdomains_from_dns(domain, subdomains)
            if subdomains:
                click.echo(f"\n[+] 通过DNS记录收集到 {len(subdomains)} 个子域名")
            
            if len(subdomains) > 0:
                click.echo(f"\n[+] 总共收集到 {len(subdomains)} 个子域名")
        
        # 第二步：对所有域名进行漏洞检测
        all_domains = [domain]
        if subdomains:
            all_domains += list(subdomains)
        click.echo("\n[*] 开始进行DNS域传送漏洞检测...")
        
        with tqdm.tqdm(all_domains, desc="检测进度") as pbar:
            for test_domain in pbar:
                pbar.set_description(f"正在检测 {test_domain}")
                domain_ns = get_nameservers(test_domain)
                if domain_ns:
                    for ns in domain_ns:
                        is_vulnerable = test_zone_transfer(test_domain, ns)
                        if is_vulnerable:
                            vulnerable_servers.append({"domain": test_domain, "nameserver": ns})
        
        # 输出结果
        click.echo("\n[*] 检测完成")
        
        # 保存当前域名的结果到文件 - 添加异常处理
        try:
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
                f.flush()  # 确保数据立即写入文件
            
            # 输出到控制台
            if vulnerable_servers:
                click.echo("\n[!] 发现存在漏洞的DNS服务器:")
                for result in vulnerable_servers:
                    click.echo(f"    - {result['domain']} -> {result['nameserver']}")
            else:
                click.echo("\n[+] 未发现存在域传送漏洞的DNS服务器")
            
            click.echo(f"[+] {domain} 的检测结果已保存到: {output}")
        except Exception as e:
            click.echo(f"[!] 保存结果到文件失败: {str(e)}")
    
    click.echo(f"\n[+] 所有检测结果已保存到: {output}")

if __name__ == '__main__':
    main()
