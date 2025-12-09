import requests
import re
import json
import os
from collections import defaultdict
from datetime import datetime
import dns.resolver
from config import (
    UPSTREAM_RULES, OUTPUT_FILE, SUPPORTED_RULE_TYPES, EXCLUDED_PREFIXES,
    DNS_SERVERS, RESOLVED_CACHE_FILE, MYLIST_FILE
)

def download_rule(url: str) -> list[str]:
    """下载单个上游规则，返回有效规则列表（过滤注释/空行）"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        response.encoding = response.apparent_encoding or "utf-8"
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

def parse_domain(rule: str) -> str | None:
    """从规则中提取纯域名（唯一标识）"""
    # 匹配 ||domain^... 或 @@||domain^... 格式，提取domain
    pattern = r"^(?:@@)?\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?"
    match = re.match(pattern, rule)
    if match:
        return match.group(1).lower()  # 统一小写，确保唯一性
    return None

def check_domain_resolvable(domain: str) -> bool:
    """检查域名是否可被指定DNS服务器解析（至少一个有A记录）"""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for server in DNS_SERVERS:
        try:
            resolver.nameservers = [server]
            resolver.query(domain, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
    return False

def load_resolved_cache() -> dict[str, bool]:
    """加载已解析域名的缓存"""
    if os.path.exists(RESOLVED_CACHE_FILE):
        try:
            with open(RESOLVED_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_resolved_cache(cache: dict[str, bool]):
    """保存已解析域名的缓存"""
    with open(RESOLVED_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

def load_mylist() -> dict[str, str]:
    """加载人工审查规则文件，返回{纯域名: 规则}"""
    mylist = {}
    if os.path.exists(MYLIST_FILE):
        with open(MYLIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                rule = line.strip()
                if not rule or rule.startswith(EXCLUDED_PREFIXES[:3]):  # 跳过注释和空行
                    continue
                domain = parse_domain(rule)
                if domain:
                    mylist[domain] = rule
    return mylist

def merge_rules(all_rules: list[str]) -> tuple[list[str], list[str], list[str]]:
    """
    整合规则：处理mylist冲突、DNS验证、黑白名单冲突
    返回：(mylist冲突规则, 黑白名单冲突规则, 普通规则)
    """
    # 加载mylist和解析缓存
    mylist = load_mylist()
    resolved_cache = load_resolved_cache()
    new_resolved = {}  # 本次运行新增的解析结果

    # 分组：按纯域名
    domain_groups = defaultdict(list)  # {纯域名: [规则列表]}

    # 处理上游规则，提取纯域名并过滤无效规则
    for rule in all_rules:
        # 转换Hosts规则
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule

        # 提取纯域名
        domain = parse_domain(final_rule)
        if not domain:
            continue  # 无法提取域名的规则跳过

        domain_groups[domain].append(final_rule)

    # 处理各组规则
    mylist_conflict_rules = []  # mylist冲突的规则（使用mylist的）
    black_white_conflict_rules = []  # 黑白名单冲突的规则（保留白名单）
    normal_rules = []  # 普通规则
    processed_domains = set()

    # 先处理mylist中的域名
    for domain, mylist_rule in mylist.items():
        processed_domains.add(domain)
        # 检查是否有上游规则冲突
        if domain in domain_groups:
            # 记录冲突，使用mylist的规则
            mylist_conflict_rules.append(f"# 人工审查区（mylist冲突）：{domain} - 使用mylist规则")
            mylist_conflict_rules.append(mylist_rule)
            mylist_conflict_rules.append(f"# 上游冲突规则：{chr(10).join(domain_groups[domain])}")
            mylist_conflict_rules.append("")  # 空行分隔
        else:
            # mylist规则无冲突，直接加入普通规则
            normal_rules.append(mylist_rule)

    # 处理非mylist的域名
    for domain, rules in domain_groups.items():
        if domain in processed_domains:
            continue  # 已处理过（mylist中的）

        # DNS解析检查（使用缓存）
        if domain in resolved_cache:
            resolvable = resolved_cache[domain]
        else:
            resolvable = check_domain_resolvable(domain)
            new_resolved[domain] = resolvable  # 记录新解析结果

        if not resolvable:
            continue  # 不可解析的域名规则删除

        # 分离白名单和黑名单规则
        whitelist_rules = [r for r in rules if r.startswith("@@||")]
        blacklist_rules = [r for r in rules if r.startswith("||") and not r.startswith("@@||")]

        # 处理黑白名单冲突
        if whitelist_rules and blacklist_rules:
            # 优先保留白名单，放入黑白冲突审查区
            black_white_conflict_rules.append(f"# 人工审查区（黑白名单冲突）：{domain} - 保留白名单")
            # 选择白名单中可能的优先级规则（带$important的）
            selected_white = None
            for r in whitelist_rules:
                if "$important" in r:
                    selected_white = r
                    break
            if not selected_white:
                selected_white = whitelist_rules[0]
            black_white_conflict_rules.append(selected_white)
            black_white_conflict_rules.append(f"# 冲突的黑名单规则：{chr(10).join(blacklist_rules)}")
            black_white_conflict_rules.append("")  # 空行分隔
        elif whitelist_rules:
            # 只有白名单，选优先级高的
            selected = None
            for r in whitelist_rules:
                if "$important" in r:
                    selected = r
                    break
            if not selected:
                selected = whitelist_rules[0]
            normal_rules.append(selected)
        elif blacklist_rules:
            # 只有黑名单，选优先级高的
            selected = None
            for r in blacklist_rules:
                if "$important" in r:
                    selected = r
                    break
            if not selected:
                selected = blacklist_rules[0]
            normal_rules.append(selected)

    # 更新并保存解析缓存
    resolved_cache.update(new_resolved)
    save_resolved_cache(resolved_cache)

    # 去重并排序普通规则
    normal_rules = sorted(list(set(normal_rules)))

    return mylist_conflict_rules, black_white_conflict_rules, normal_rules

def generate_final_file(mylist_conflict: list[str], black_white_conflict: list[str], normal_rules: list[str]):
    """生成最终的合并规则文件，包含人工审查区和普通规则区"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    header = f"""# AdGuard Home 合并规则文件
# 自动生成：下载上游规则 → 格式转换 → 泛化合并 → 冲突处理 → DNS验证
# 上游规则来源：
{chr(10).join([f"- {url}" for url in UPSTREAM_RULES])}
# 规则数量：{len(normal_rules) + len(mylist_conflict) // 4 + len(black_white_conflict) // 4}  # 用于README自动提取
# 最后更新时间：{current_time}  # 精确到秒，用于README自动提取
# 维护者：guandasheng（GitHub 用户名）
# 定时更新：每 8 小时自动同步上游规则
# 优化说明：
# 1. Hosts 规则已转换为 AdGuard 格式（||域名^）
# 2. 基于纯域名处理，相同域名优先保留白名单规则
# 3. 与mylist.txt冲突时，保留mylist规则并标记
# 4. 域名需通过223.5.5.5和8.8.8.8解析验证，否则移除
# 5. 人工审查区包含冲突规则，供手动筛选

"""
    # 人工审查区（mylist冲突）
    mylist_section = []
    if mylist_conflict:
        mylist_section = [
            "\n# ========== 人工审查区：mylist冲突规则 ==========",
            "# 以下规则与mylist.txt中的规则冲突，已使用mylist版本",
            "# 建议检查并确认是否保留",
            ""
        ] + mylist_conflict

    # 人工审查区（黑白名单冲突）
    black_white_section = []
    if black_white_conflict:
        black_white_section = [
            "\n# ========== 人工审查区：黑白名单冲突规则 ==========",
            "# 以下规则存在相同域名的黑白名单冲突，已保留白名单版本",
            "# 建议检查并确认是否保留",
            ""
        ] + black_white_conflict

    # 普通规则区
    normal_section = [
        "\n# ========== 标准规则区 ==========",
        "# 经过验证的有效规则，无冲突",
        ""
    ] + normal_rules

    # 合并所有部分
    all_content = [header] + mylist_section + black_white_section + normal_section

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_content))
    
    print(f"\n🎉 合并完成！文件已保存至：{OUTPUT_FILE}")
    print(f"📊 最终规则数量（普通区）：{len(normal_rules)}")
    print(f"🔍 人工审查区（mylist冲突）：{len(mylist_conflict) // 4} 组")
    print(f"🔍 人工审查区（黑白冲突）：{len(black_white_conflict) // 4} 组")


def main():
    print("===== AdGuard Home 规则整合工具（优化版） =====")
    print(f"📥 正在下载 {len(UPSTREAM_RULES)} 个上游规则...")
    
    all_rules = []
    for url in UPSTREAM_RULES:
        rules = download_rule(url)
        all_rules.extend(rules)
    
    print(f"\n📦 总下载规则数：{len(all_rules)}")
    print("🔧 正在整合规则（DNS验证 + mylist处理 + 冲突解决）...")
    
    mylist_conflict, black_white_conflict, normal_rules = merge_rules(all_rules)
    generate_final_file(mylist_conflict, black_white_conflict, normal_rules)

if __name__ == "__main__":
    main()
