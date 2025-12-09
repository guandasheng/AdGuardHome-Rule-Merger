import requests
import re
import json
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed  # 移除Thread导入
from config import UPSTREAM_RULES, OUTPUT_FILE, SUPPORTED_RULE_TYPES, EXCLUDED_PREFIXES, DNS_SERVERS, RESOLVED_CACHE_FILE

# 线程安全的计数器和锁
progress_counter = 0
progress_lock = threading.Lock()
total_rules = 0

def load_resolved_cache() -> dict:
    """加载已解析域名的缓存"""
    try:
        with open(RESOLVED_CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_resolved_cache(cache: dict):
    """保存域名解析缓存"""
    with open(RESOLVED_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

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

def extract_rule_parts(rule: str) -> tuple[str, str, bool, bool]:
    """解析规则：返回（基础域名/泛化域名, 完整规则, 是否白名单, 是否带important）"""
    whitelist_pattern = r"^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?$"
    blacklist_pattern = r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?$"
    
    is_whitelist = False
    has_important = False
    base_domain = ""
    generalized_domain = ""
    
    whitelist_match = re.match(whitelist_pattern, rule)
    if whitelist_match:
        is_whitelist = True
        base_domain = whitelist_match.group(1)
        params = whitelist_match.group(2) or ""
        if "$important" in params:
            has_important = True
    else:
        blacklist_match = re.match(blacklist_pattern, rule)
        if blacklist_match:
            base_domain = blacklist_match.group(1)
            params = blacklist_match.group(2) or ""
            if "$important" in params:
                has_important = True
    
    if base_domain:
        num_pattern = r"^([a-zA-Z]+)\d+\.(.*)$"
        num_match = re.match(num_pattern, base_domain)
        if num_match:
            generalized_domain = f"{num_match.group(1)}*.{num_match.group(2)}"
        else:
            generalized_domain = base_domain
    
    return (generalized_domain, rule, is_whitelist, has_important)

def merge_rules(all_rules: list[str]) -> list[str]:
    """整合规则：泛化合并、黑白名单冲突处理、优先级保留"""
    rule_groups = defaultdict(dict)
    
    for rule in all_rules:
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule
        
        if not any(final_rule.startswith(prefix) for prefix in ["||", "@@||"]):
            continue
        
        generalized_domain, full_rule, is_whitelist, has_important = extract_rule_parts(final_rule)
        if not generalized_domain:
            continue
        
        domain_group = rule_groups[generalized_domain]
        
        if is_whitelist:
            if is_whitelist not in domain_group:
                domain_group[is_whitelist] = {}
            if has_important or not domain_group[is_whitelist]:
                domain_group[is_whitelist][has_important] = full_rule
        else:
            if True not in domain_group:
                if is_whitelist not in domain_group:
                    domain_group[is_whitelist] = {}
                if has_important or not domain_group[is_whitelist]:
                    domain_group[is_whitelist][has_important] = full_rule
    
    final_rules = []
    for domain, groups in rule_groups.items():
        if True in groups:
            whitelist_group = groups[True]
            if True in whitelist_group:
                final_rules.append(whitelist_group[True])
            else:
                final_rules.append(next(iter(whitelist_group.values())))
        else:
            blacklist_group = groups[False]
            if True in blacklist_group:
                final_rules.append(blacklist_group[True])
            else:
                final_rules.append(next(iter(blacklist_group.values())))
    
    final_rules.sort()
    return final_rules

def resolve_domain(domain: str, dns_servers: list[str], retries: int = 2) -> bool:
    """解析域名，支持重试和多服务器切换"""
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 5
    resolver.lifetime = 10

    for _ in range(retries):
        for server in dns_servers:
            try:
                resolver.nameservers = [server]
                answers = resolver.resolve(domain, 'A')
                return len(answers) > 0
            except dns.resolver.NXDOMAIN:
                return False
            except (dns.resolver.Timeout, dns.resolver.NoNameservers, dns.resolver.SERVFAIL):
                continue
            except Exception:
                continue
    return False

def extract_original_domain(rule: str) -> str:
    """从规则中提取原始域名"""
    if rule.startswith("@@||"):
        match = re.match(r"^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)", rule)
    elif rule.startswith("||"):
        match = re.match(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)", rule)
    else:
        return ""
    return match.group(1) if match else ""

def process_rule(rule: str, resolved_cache: dict, cache_lock: threading.Lock) -> str | None:
    """处理单个规则（线程安全）"""
    global progress_counter, total_rules
    
    original_domain = extract_original_domain(rule)
    if not original_domain:
        with progress_lock:
            global progress_counter
            progress_counter += 1
        return rule
    
    # 检查缓存
    with cache_lock:
        if original_domain in resolved_cache:
            is_valid = resolved_cache[original_domain]
            with progress_lock:
                progress_counter += 1
            return rule if is_valid else None
    
    # 解析域名
    try:
        is_valid = resolve_domain(original_domain, DNS_SERVERS)
        with cache_lock:
            resolved_cache[original_domain] = is_valid
        with progress_lock:
            progress_counter += 1
        return rule if is_valid else None
    except Exception as e:
        print(f" | 解析错误 - {original_domain}: {str(e)}")
        with progress_lock:
            progress_counter += 1
        return rule  # 解析错误时保留规则

def filter_unresolvable_domains(rules: list[str]) -> list[str]:
    """多线程过滤无法解析的域名规则"""
    global total_rules, progress_counter
    total_rules = len(rules)
    progress_counter = 0
    resolved_cache = load_resolved_cache()
    cache_lock = threading.Lock()
    valid_rules = []
    
    print(f"开始过滤无效域名（总规则数：{total_rules}，线程数：100）...")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(process_rule, rule, resolved_cache, cache_lock) for rule in rules]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_rules.append(result)
            
            # 显示进度
            with progress_lock:
                progress = (progress_counter / total_rules) * 100
                if progress_counter % 100 == 0 or progress_counter == total_rules:
                    print(f"\r[{'#' * int(progress / 2)}{'-' * (50 - int(progress / 2))}] {progress:.1f}% | {progress_counter}/{total_rules}", end="")
    
    print()
    save_resolved_cache(resolved_cache)
    return valid_rules

def generate_final_file(rules: list[str]):
    """生成最终的合并规则文件"""
    from datetime import datetime
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    header = f"""# AdGuard Home 合并规则文件
# 自动生成：下载上游规则 → 格式转换 → 泛化合并 → 冲突处理 → 无效域名过滤
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
# 5. 过滤无法解析的无效域名（多线程处理）
# 6. 所有规则已去重并按域名排序

"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(rules))
    
    print(f"\n🎉 合并完成！文件已保存至：{OUTPUT_FILE}")
    print(f"📊 最终规则数量：{len(rules)}")


def main():
    print("===== AdGuard Home 规则整合工具（多线程优化版） =====")
    print(f"📥 正在下载 {len(UPSTREAM_RULES)} 个上游规则...")
    
    all_rules = []
    for url in UPSTREAM_RULES:
        rules = download_rule(url)
        all_rules.extend(rules)
    
    print(f"\n📦 总下载规则数：{len(all_rules)}")
    if len(all_rules) == 0:
        print("⚠️ 警告：未获取到任何有效规则，可能上游链接全部失效")
        return
    
    print("🔧 正在整合规则（泛化合并 + 优先级处理 + 冲突解决）...")
    merged_rules = merge_rules(all_rules)
    
    print("🔍 正在过滤无效域名（多线程模式）...")
    valid_rules = filter_unresolvable_domains(merged_rules)
    
    generate_final_file(valid_rules)

if __name__ == "__main__":
    main()
