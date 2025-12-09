import requests
import re
import json
import time
from collections import defaultdict
from config import UPSTREAM_RULES, OUTPUT_FILE, SUPPORTED_RULE_TYPES, EXCLUDED_PREFIXES, DNS_SERVERS, RESOLVED_CACHE_FILE
import dns.resolver  # 需要新增这个依赖

def print_progress(current, total, status=""):
    """显示进度条"""
    percent = current / total * 100 if total > 0 else 100
    bar_length = 40
    filled_length = int(bar_length * current // total) if total > 0 else bar_length
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    print(f'\r[{bar}] {percent:.1f}% | {current}/{total} | {status}', end='', flush=True)
    if current == total:
        print()  # 进度完成后换行

def load_resolved_cache():
    """加载已解析的域名缓存"""
    try:
        with open(RESOLVED_CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_resolved_cache(cache):
    """保存域名解析缓存"""
    with open(RESOLVED_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

def resolve_domain(domain, dns_servers):
    """解析域名，返回是否有效"""
    for server in dns_servers:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            answers = resolver.resolve(domain, 'A')
            for answer in answers:
                ip = str(answer)
                if ip != '0.0.0.0':
                    return True
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer):
            continue
    return False

def download_rule(url: str) -> list[str]:
    """下载单个上游规则，返回有效规则列表（过滤注释/空行）"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=60, allow_redirects=True)
        response.raise_for_status()
        response.encoding = "utf-8"
        rules = response.text.split("\n")
        comment_prefixes = EXCLUDED_PREFIXES[:3]
        valid_rules = [
            rule.strip() for rule in rules
            if rule.strip() and not rule.strip().startswith(comment_prefixes)
        ]
        print(f"✅ 成功下载 {url} | 有效规则数：{len(valid_rules)}")
        return valid_rules
    except requests.exceptions.ConnectionError:
        print(f"❌ 下载失败 {url} | 错误：网络连接超时/无法访问")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"❌ 下载失败 {url} | 错误：HTTP 状态码 {e.response.status_code}")
        return []
    except Exception as e:
        print(f"❌ 下载失败 {url} | 错误：{str(e)}")
        return []

def convert_hosts_to_adguard(rule: str) -> str | None:
    """将 Hosts 规则转换为 AdGuard 规则 ||域名^"""
    hosts_pattern = r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]+)"
    match = re.match(hosts_pattern, rule)
    if match:
        domain = match.group(2)
        return f"||{domain}^"
    return None

def extract_rule_parts(rule: str) -> tuple[str, str, bool, bool, str]:
    """解析规则：返回（基础域名/泛化域名, 完整规则, 是否白名单, 是否带important, 原始域名）"""
    # 匹配白名单规则 @@||域名^$参数 或 @@||域名^
    whitelist_pattern = r"^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?$"
    # 匹配黑名单规则 ||域名^$参数 或 ||域名^
    blacklist_pattern = r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?$"
    
    is_whitelist = False
    has_important = False
    base_domain = ""
    generalized_domain = ""
    original_domain = ""
    
    # 处理白名单
    whitelist_match = re.match(whitelist_pattern, rule)
    if whitelist_match:
        is_whitelist = True
        original_domain = whitelist_match.group(1)
        base_domain = original_domain
        params = whitelist_match.group(2) or ""
        if "$important" in params:
            has_important = True
    else:
        # 处理黑名单
        blacklist_match = re.match(blacklist_pattern, rule)
        if blacklist_match:
            original_domain = blacklist_match.group(1)
            base_domain = original_domain
            params = blacklist_match.group(2) or ""
            if "$important" in params:
                has_important = True
    
    if base_domain:
        # 生成泛化域名（如 a36243.actonservice.com → a*.actonservice.com）
        num_pattern = r"^([a-zA-Z]+)\d+\.(.*)$"
        num_match = re.match(num_pattern, base_domain)
        if num_match:
            generalized_domain = f"{num_match.group(1)}*.{num_match.group(2)}"
        else:
            generalized_domain = base_domain
    
    return (generalized_domain, rule, is_whitelist, has_important, original_domain)

def merge_rules(all_rules: list[str]) -> list[str]:
    """整合规则：泛化合并、黑白名单冲突处理、优先级保留"""
    rule_groups = defaultdict(dict)  # key: 泛化域名, value: {is_whitelist: {has_important: rule}}
    
    for i, rule in enumerate(all_rules):
        # 显示处理进度
        print_progress(i + 1, len(all_rules), f"处理规则: {rule[:50]}...")
        
        # 转换 Hosts 规则
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule
        
        # 过滤不支持的规则
        if not any(final_rule.startswith(prefix) for prefix in ["||", "@@||"]):
            continue
        
        # 解析规则部分
        generalized_domain, full_rule, is_whitelist, has_important, _ = extract_rule_parts(final_rule)
        if not generalized_domain:
            continue
        
        # 按泛化域名分组处理
        domain_group = rule_groups[generalized_domain]
        
        # 白名单优先级 > 黑名单
        if is_whitelist:
            if is_whitelist not in domain_group:
                domain_group[is_whitelist] = {}
            if has_important or not domain_group[is_whitelist]:
                domain_group[is_whitelist][has_important] = full_rule
        else:
            # 黑名单：仅当没有白名单时才处理
            if True not in domain_group:  # 无白名单
                if is_whitelist not in domain_group:
                    domain_group[is_whitelist] = {}
                if has_important or not domain_group[is_whitelist]:
                    domain_group[is_whitelist][has_important] = full_rule
    
    # 生成最终规则列表
    final_rules = []
    for domain, groups in rule_groups.items():
        if True in groups:  # 存在白名单
            whitelist_group = groups[True]
            if True in whitelist_group:
                final_rules.append(whitelist_group[True])
            else:
                final_rules.append(next(iter(whitelist_group.values())))
        else:  # 仅黑名单
            blacklist_group = groups[False]
            if True in blacklist_group:
                final_rules.append(blacklist_group[True])
            else:
                final_rules.append(next(iter(blacklist_group.values())))
    
    # 按域名排序
    final_rules.sort()
    return final_rules

def filter_unresolvable_domains(rules):
    """过滤无法解析的域名规则"""
    resolved_cache = load_resolved_cache()
    valid_rules = []
    new_entries = 0
    
    print(f"\n🔍 开始验证域名解析状态（使用DNS服务器: {', '.join(DNS_SERVERS)}）")
    time.sleep(0.1)  # 确保输出能被正确捕获
    
    for i, rule in enumerate(rules):
        # 提取原始域名
        _, _, _, _, original_domain = extract_rule_parts(rule)
        if not original_domain:
            valid_rules.append(rule)
            print_progress(i + 1, len(rules), f"跳过无效格式规则")
            continue
        
        # 检查缓存
        if original_domain in resolved_cache:
            if resolved_cache[original_domain]:
                valid_rules.append(rule)
            print_progress(i + 1, len(rules), f"已缓存 - {original_domain}")
            continue
        
        # 需要解析的新域名
        new_entries += 1
        is_valid = resolve_domain(original_domain, DNS_SERVERS)
        resolved_cache[original_domain] = is_valid
        
        if is_valid:
            valid_rules.append(rule)
            status = f"有效 - {original_domain}"
        else:
            status = f"无效 - {original_domain}"
        
        print_progress(i + 1, len(rules), status)
        time.sleep(0.01)  # 稍微延迟，避免输出过快
    
    # 保存更新后的缓存
    save_resolved_cache(resolved_cache)
    print(f"\n📊 域名验证完成：总规则 {len(rules)}，有效规则 {len(valid_rules)}，新增缓存 {new_entries}")
    return valid_rules

def generate_final_file(rules: list[str]):
    """生成最终的合并规则文件"""
    from datetime import datetime
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    header = f"""# AdGuard Home 合并规则文件
# 自动生成：下载上游规则 → 格式转换 → 泛化合并 → 冲突处理 → 域名解析验证
# 上游规则来源：
{chr(10).join([f"- {url}" for url in UPSTREAM_RULES])}
# 规则数量：{len(rules)}  # 用于README自动提取（请勿修改此行格式）
# 最后更新时间：{current_time}  # 用于README自动提取（请勿修改此行格式）
# 维护者：guandasheng（GitHub 用户名）
# 定时更新：每 8 小时自动同步上游规则
# 优化说明：
# 1. Hosts 规则已转换为 AdGuard 格式（||域名^）
# 2. 数字后缀子域名自动泛化（如 a36243.actonservice.com → a*.actonservice.com）
# 3. 黑白名单冲突时，优先保留白名单规则
# 4. 相同域名保留带 $important 优先级的规则
# 5. 所有规则已去重并按域名排序
# 6. 已过滤无法解析或解析为0.0.0.0的域名

"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(rules))
    
    print(f"\n🎉 合并完成！文件已保存至：{OUTPUT_FILE}")
    print(f"📊 最终规则数量：{len(rules)}")


def main():
    print("===== AdGuard Home 规则整合工具（优化版） =====")
    print(f"📥 正在下载 {len(UPSTREAM_RULES)} 个上游规则...")
    
    all_rules = []
    for i, url in enumerate(UPSTREAM_RULES):
        print(f"[{i+1}/{len(UPSTREAM_RULES)}] 下载中: {url}")
        rules = download_rule(url)
        all_rules.extend(rules)
        print_progress(i + 1, len(UPSTREAM_RULES), f"已下载 {len(all_rules)} 条规则")
    
    print(f"\n📦 总下载规则数：{len(all_rules)}")
    if len(all_rules) == 0:
        print("⚠️ 警告：未获取到任何有效规则，可能上游链接全部失效")
        return
    
    print("\n🔧 正在整合规则（泛化合并 + 优先级处理 + 冲突解决）...")
    merged_rules = merge_rules(all_rules)
    print(f"🔧 规则整合完成，合并后规则数：{len(merged_rules)}")
    
    # 过滤无法解析的域名
    valid_rules = filter_unresolvable_domains(merged_rules)
    
    generate_final_file(valid_rules)

if __name__ == "__main__":
    main()
