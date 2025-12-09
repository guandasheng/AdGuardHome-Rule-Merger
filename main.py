import requests
import re
import dns.resolver
from dns.resolver import NoNameservers, NXDOMAIN, Timeout
from dns.exception import DNSException
from collections import defaultdict
from datetime import datetime
from config import UPSTREAM_RULES, OUTPUT_FILE, SUPPORTED_RULE_TYPES, EXCLUDED_PREFIXES

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
        comment_prefixes = EXCLUDED_PREFIXES[:3]  # 提取注释前缀（!, #, //）
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

def check_domain_resolvable(domain: str) -> bool:
    """检查域名是否可解析（处理异常并使用新方法）"""
    resolver = dns.resolver.Resolver()
    # 指定可靠的DNS服务器，避免默认服务器解析失败
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '223.5.5.5']
    
    try:
        # 使用新方法 resolve() 替代 deprecated 的 query()
        resolver.resolve(domain, 'A')
        return True  # 解析成功
    except (NoNameservers, NXDOMAIN, Timeout, DNSException):
        # 捕获所有可能的DNS异常，避免单个域名解析失败导致脚本崩溃
        return False  # 解析失败

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
    """整合规则：泛化合并、黑白名单冲突处理、优先级保留、DNS验证"""
    rule_groups = defaultdict(dict)  # key: 泛化域名, value: {is_whitelist: {has_important: rule}}
    
    for rule in all_rules:
        # 转换 Hosts 规则为 AdGuard 格式
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule
        
        # 过滤不支持的规则类型
        if not any(final_rule.startswith(prefix) for prefix in ["||", "@@||"]):
            continue
        
        # 解析规则组成部分
        generalized_domain, full_rule, is_whitelist, has_important, original_domain = extract_rule_parts(final_rule)
        if not generalized_domain:
            continue
        
        # DNS验证：仅保留可解析的域名（可选逻辑，根据需求调整）
        # 注意：白名单通常需要保留，即使域名不可解析
        if not is_whitelist and not check_domain_resolvable(original_domain):
            continue  # 跳过不可解析的黑名单域名
        
        # 按泛化域名分组处理规则优先级
        domain_group = rule_groups[generalized_domain]
        
        # 白名单优先级 > 黑名单
        if is_whitelist:
            if is_whitelist not in domain_group:
                domain_group[is_whitelist] = {}
            # 保留带important的规则，或更新为更高优先级规则
            if has_important or not domain_group[is_whitelist]:
                domain_group[is_whitelist][has_important] = full_rule
        else:
            # 黑名单：仅当没有白名单时才处理
            if True not in domain_group:  # 无白名单规则
                if is_whitelist not in domain_group:
                    domain_group[is_whitelist] = {}
                # 保留带important的规则，或更新为更高优先级规则
                if has_important or not domain_group[is_whitelist]:
                    domain_group[is_whitelist][has_important] = full_rule
    
    # 生成最终规则列表
    final_rules = []
    for domain, groups in rule_groups.items():
        if True in groups:  # 优先选择白名单
            whitelist_group = groups[True]
            if True in whitelist_group:
                final_rules.append(whitelist_group[True])
            else:
                final_rules.append(next(iter(whitelist_group.values())))
        else:  # 仅保留黑名单
            blacklist_group = groups[False]
            if True in blacklist_group:
                final_rules.append(blacklist_group[True])
            else:
                final_rules.append(next(iter(blacklist_group.values())))
    
    # 按域名排序，保证规则有序性
    final_rules.sort()
    return final_rules

def generate_final_file(rules: list[str]):
    """生成最终的合并规则文件，包含元信息"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 精确到秒
    
    header = f"""# AdGuard Home 合并规则文件
# 自动生成流程：下载上游规则 → 格式转换 → 泛化合并 → 冲突处理 → DNS验证
# 上游规则来源：
{chr(10).join([f"- {url}" for url in UPSTREAM_RULES])}
# 规则数量：{len(rules)}  # 用于README自动提取
# 最后更新时间：{current_time}  # 用于README自动提取
# 维护者：guandasheng（GitHub 用户名）
# 定时更新：每 8 小时自动同步上游规则
# 优化说明：
# 1. Hosts 规则已转换为 AdGuard 格式（||域名^）
# 2. 数字后缀子域名自动泛化（如 a36243.actonservice.com → a*.actonservice.com）
# 3. 黑白名单冲突时，优先保留白名单规则
# 4. 相同域名保留带 $important 优先级的规则
# 5. 黑名单规则自动过滤不可解析的无效域名
# 6. 所有规则已去重并按域名排序

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
    for url in UPSTREAM_RULES:
        rules = download_rule(url)
        all_rules.extend(rules)
    
    print(f"\n📦 总下载规则数：{len(all_rules)}")
    print("🔧 正在整合规则（DNS验证 + 泛化合并 + 优先级处理 + 冲突解决）...")
    
    merged_rules = merge_rules(all_rules)
    generate_final_file(merged_rules)

if __name__ == "__main__":
    main()
