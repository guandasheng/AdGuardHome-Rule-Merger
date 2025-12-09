import requests
import re
import json
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from config import UPSTREAM_RULES, OUTPUT_FILE, SUPPORTED_RULE_TYPES, EXCLUDED_PREFIXES, DNS_SERVERS, RESOLVED_CACHE_FILE, MYLIST_FILE

# 线程安全的计数器和锁
progress_counter = 0
progress_lock = threading.Lock()
total_rules = 0
# 新增活跃线程计数器用于监控
active_threads = 0
active_threads_lock = threading.Lock()

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

def resolve_domain(domain: str, dns_servers: list[str], retries: int = 1) -> bool:
    """解析域名，优化超时设置，减少重试次数"""
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = 3  # 缩短超时时间
    resolver.lifetime = 5  # 缩短总生命周期

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
            except Exception as e:
                # 记录具体错误但不阻塞
                print(f"⚠️ 解析异常 {domain}@{server}: {str(e)}")
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
    """处理单个规则（线程安全），增加线程监控"""
    global progress_counter
    
    # 监控活跃线程数
    with active_threads_lock:
        global active_threads
        active_threads += 1
    
    try:
        original_domain = extract_original_domain(rule)
        if not original_domain:
            with progress_lock:
                progress_counter += 1
            return rule
        
        # 检查缓存
        with cache_lock:
            if original_domain in resolved_cache:
                is_valid = resolved_cache[original_domain]
                with progress_lock:
                    progress_counter += 1
                return rule if is_valid else None
        
        # 解析域名（新增超时保护）
        start_time = time.time()
        is_valid = resolve_domain(original_domain, DNS_SERVERS)
        elapsed = time.time() - start_time
        
        # 记录慢查询
        if elapsed > 3:
            print(f"⏱️ 慢解析 {original_domain} 耗时 {elapsed:.2f}s")
        
        with cache_lock:
            resolved_cache[original_domain] = is_valid
        with progress_lock:
            progress_counter += 1
        return rule if is_valid else None
    
    except Exception as e:
        print(f"❌ 处理错误 {original_domain}: {str(e)}")
        with progress_lock:
            progress_counter += 1
        return rule  # 解析错误时保留规则
    
    finally:
        # 减少活跃线程计数
        with active_threads_lock:
            active_threads -= 1

def filter_unresolvable_domains(rules: list[str]) -> list[str]:
    """多线程过滤无法解析的域名规则，增加超时控制和进度监控"""
    global total_rules, progress_counter, active_threads
    total_rules = len(rules)
    progress_counter = 0
    active_threads = 0
    resolved_cache = load_resolved_cache()
    cache_lock = threading.Lock()
    valid_rules = []
    
    # 计算需要检测的新域名数量
    new_domains_count = sum(1 for rule in rules 
                          if extract_original_domain(rule) not in resolved_cache)
    print(f"开始过滤无效域名（总规则数：{total_rules}，需检测新域名：{new_domains_count}，线程数：50）...")
    
    # 减少线程池大小，避免资源竞争
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(process_rule, rule, resolved_cache, cache_lock): rule for rule in rules}
        completed = 0
        
        # 增加整体超时控制
        while completed < len(futures):
            # 每次等待10秒，超时的任务强制取消
            done, not_done = concurrent.futures.wait(futures, timeout=10)
            
            for future in done:
                try:
                    result = future.result()
                    if result:
                        valid_rules.append(result)
                    completed += 1
                except Exception as e:
                    print(f"⚠️ 任务异常: {str(e)}")
                    completed += 1
            
            # 处理超时未完成的任务
            for future in not_done:
                rule = futures[future]
                domain = extract_original_domain(rule)
                print(f"⏰ 任务超时 {domain}，强制继续")
                # 超时任务结果视为有效（避免误删）
                valid_rules.append(rule)
                future.cancel()
                completed += 1
                with progress_lock:
                    progress_counter += 1
            
            # 实时显示进度和线程状态
            with progress_lock, active_threads_lock:
                progress = (progress_counter / total_rules) * 100
                print(f"\r[{'#' * int(progress / 2)}{'-' * (50 - int(progress / 2))}] {progress:.1f}% | {progress_counter}/{total_rules} | 活跃线程: {active_threads}", end="")
    
    print()
    save_resolved_cache(resolved_cache)
    return valid_rules

def load_mylist_rules() -> list[str]:
    """加载本地人工审查规则"""
    try:
        with open(MYLIST_FILE, 'r', encoding='utf-8') as f:
            rules = f.readlines()
        # 过滤注释和空行但保留有效规则
        valid_rules = [
            rule.strip() for rule in rules
            if rule.strip() and not rule.strip().startswith(('#', '!', '//'))
        ]
        print(f"✅ 加载本地规则 {MYLIST_FILE} | 有效规则数：{len(valid_rules)}")
        return valid_rules
    except FileNotFoundError:
        print(f"⚠️ 未找到本地规则文件 {MYLIST_FILE}，跳过加载")
        return []
    except Exception as e:
        print(f"❌ 加载本地规则失败：{str(e)}")
        return []

def generate_final_file(rules: list[str]):
    """生成最终的合并规则文件，包含本地规则"""
    from datetime import datetime
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # 加载并合并本地规则
    mylist_rules = load_mylist_rules()
    final_rules = rules + mylist_rules
    # 去重处理
    final_rules = list(sorted(set(final_rules)))
    
    header = f"""# AdGuard Home 合并规则文件
# 自动生成：下载上游规则 → 格式转换 → 泛化合并 → 冲突处理 → 无效域名过滤
# 上游规则来源：
{chr(10).join([f"- {url}" for url in UPSTREAM_RULES])}
# 规则数量：{len(final_rules)}  # 用于README自动提取（请勿修改此行格式）
# 最后更新时间：{current_time}  # 用于README自动提取（请勿修改此行格式）
# 维护者：guandasheng（GitHub 用户名）
# 定时更新：每 8 小时自动同步上游规则
# 优化说明：
# 1. Hosts 规则已转换为 AdGuard 格式（||域名^）
# 2. 数字后缀子域名自动泛化（如 a36243.actonservice.com → a*.actonservice.com）
# 3. 黑白名单冲突时，优先保留白名单规则
# 4. 相同域名保留带 $important 优先级的规则
# 5. 自动过滤无效域名，优化了解析超时问题
"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(header + '\n'.join(final_rules) + '\n')
    print(f"✅ 规则文件生成完成，保存至 {OUTPUT_FILE}（共 {len(final_rules)} 条规则）")

def main():
    """主函数：执行规则下载、合并、过滤、生成完整流程"""
    print("====== 开始执行 AdGuard Home 规则合并 ======")
    
    # 1. 下载所有上游规则
    all_rules = []
    for url in UPSTREAM_RULES:
        rules = download_rule(url)
        all_rules.extend(rules)
    print(f"📊 下载完成，原始规则总数：{len(all_rules)}")
    
    # 2. 合并去重规则
    merged_rules = merge_rules(all_rules)
    print(f"🔗 规则合并完成，去重后总数：{len(merged_rules)}")
    
    # 3. 过滤无效域名（核心优化部分）
    valid_rules = filter_unresolvable_domains(merged_rules)
    print(f"🎯 无效域名过滤完成，有效规则数：{len(valid_rules)}")
    
    # 4. 生成最终规则文件
    generate_final_file(valid_rules)
    print("====== 规则合并流程执行完毕 ======")

if __name__ == "__main__":
    import concurrent.futures  # 确保导入用于超时控制
    main()
