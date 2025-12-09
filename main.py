import requests
import re
from collections import defaultdict
from config import UPSTREAM_RULES, OUTPUT_FILE, EXCLUDED_PREFIXES, MYLIST_FILE

def load_mylist_rules() -> list[str]:
    """加载本地mylist规则，过滤注释和空行"""
    try:
        with open(MYLIST_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        # 过滤注释（#/!/\/\/开头）和空行
        valid_rules = [
            line.strip() for line in lines
            if line.strip() and not line.strip().startswith(('#', '!', '//'))
        ]
        print(f"✅ 成功加载本地规则 {MYLIST_FILE} | 有效规则数：{len(valid_rules)}")
        return valid_rules
    except Exception as e:
        print(f"❌ 加载本地规则失败 {MYLIST_FILE} | 错误：{str(e)}")
        return []

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
    # 匹配白名单规则 @@||域名^$参数 或 @@||域名^
    whitelist_pattern = r"^@@\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?$"
    # 匹配黑名单规则 ||域名^$参数 或 ||域名^
    blacklist_pattern = r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)(\^.*)?$"
    
    is_whitelist = False
    has_important = False
    base_domain = ""
    generalized_domain = ""
    
    # 处理白名单
    whitelist_match = re.match(whitelist_pattern, rule)
    if whitelist_match:
        is_whitelist = True
        base_domain = whitelist_match.group(1)
        params = whitelist_match.group(2) or ""
        if "$important" in params:
            has_important = True
    else:
        # 处理黑名单
        blacklist_match = re.match(blacklist_pattern, rule)
        if blacklist_match:
            base_domain = blacklist_match.group(1)
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
    
    return (generalized_domain, rule, is_whitelist, has_important)

def merge_rules(mylist_rules: list[str], upstream_rules: list[str]) -> list[str]:
    """整合规则：本地规则优先，泛化合并、黑白名单冲突处理、优先级保留"""
    rule_groups = defaultdict(dict)  # key: 泛化域名, value: {is_whitelist: {has_important: rule}}
    mylist_domains = set()  # 存储mylist中已有的泛化域名
    
    # 第一步：处理本地规则（最高优先级）
    for rule in mylist_rules:
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule
        
        if not any(final_rule.startswith(prefix) for prefix in ["||", "@@||"]):
            continue
        
        generalized_domain, full_rule, is_whitelist, has_important = extract_rule_parts(final_rule)
        if not generalized_domain:
            continue
        
        # 添加到本地域名集合
        mylist_domains.add(generalized_domain)
        
        # 存储本地规则
        domain_group = rule_groups[generalized_domain]
        if is_whitelist not in domain_group:
            domain_group[is_whitelist] = {}
        # 本地规则直接覆盖，不考虑是否有important
        domain_group[is_whitelist][has_important] = full_rule
    
    # 第二步：处理上游规则（仅保留本地规则中不存在的泛化域名）
    for rule in upstream_rules:
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule
        
        if not any(final_rule.startswith(prefix) for prefix in ["||", "@@||"]):
            continue
        
        generalized_domain, full_rule, is_whitelist, has_important = extract_rule_parts(final_rule)
        if not generalized_domain:
            continue
        
        # 若泛化域名已存在于本地规则，则跳过上游规则
        if generalized_domain in mylist_domains:
            continue
        
        # 处理上游规则
        domain_group = rule_groups[generalized_domain]
        if is_whitelist:
            if is_whitelist not in domain_group:
                domain_group[is_whitelist] = {}
            # 上游规则：有important的优先，或者当前没有规则时添加
            if has_important or not domain_group[is_whitelist]:
                domain_group[is_whitelist][has_important] = full_rule
        else:
            # 黑名单：仅当没有白名单时才处理
            if True not in domain_group:
                if is_whitelist not in domain_group:
                    domain_group[is_whitelist] = {}
                if has_important or not domain_group[is_whitelist]:
                    domain_group[is_whitelist][has_important] = full_rule
    
    # 生成最终规则列表
    final_rules = []
    for domain, groups in rule_groups.items():
        if True in groups:  # 存在白名单
            whitelist_group = groups[True]
            # 优先选择带important的规则
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

def generate_final_file(rules: list[str]):
    """生成最终的合并规则文件"""
    from datetime import datetime
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    header = f"""# AdGuard Home 合并规则文件
# 自动生成：下载上游规则 → 格式转换 → 泛化合并 → 冲突处理
# 上游规则来源：
{chr(10).join([f"- {url}" for url in UPSTREAM_RULES])}
# 本地规则来源：{MYLIST_FILE}
# 规则数量：{len(rules)}  # 用于README自动提取（请勿修改此行格式）
# 最后更新时间：{current_time}  # 用于README自动提取（请勿修改此行格式）
# 维护者：guandasheng（GitHub 用户名）
# 定时更新：每 8 小时自动同步上游规则
# 优化说明：
# 1. Hosts 规则已转换为 AdGuard 格式（||域名^）
# 2. 数字后缀子域名自动泛化（如 a36243.actonservice.com → a*.actonservice.com）
# 3. 本地规则(mylist.txt)优先级最高，会覆盖上游所有相同域名规则
# 4. 相同域名保留带 $important 优先级的规则
# 5. 所有规则已去重并按域名排序

"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(rules))
    
    print(f"\n🎉 合并完成！文件已保存至：{OUTPUT_FILE}")
    print(f"📊 最终规则数量：{len(rules)}")


def main():
    print("===== AdGuard Home 规则整合工具（优化版） =====")
    
    # 加载本地规则
    mylist_rules = load_mylist_rules()
    
    # 下载上游规则
    print(f"📥 正在下载 {len(UPSTREAM_RULES)} 个上游规则...")
    all_upstream_rules = []
    for url in UPSTREAM_RULES:
        rules = download_rule(url)
        all_upstream_rules.extend(rules)
    
    print(f"\n📦 本地规则数：{len(mylist_rules)} | 上游总规则数：{len(all_upstream_rules)}")
    if len(mylist_rules) == 0 and len(all_upstream_rules) == 0:
        print("⚠️ 警告：未获取到任何有效规则，可能上游链接全部失效")
    
    # 合并规则（本地规则优先）
    print("🔧 正在整合规则（本地规则优先 + 泛化合并 + 优先级处理）...")
    merged_rules = merge_rules(mylist_rules, all_upstream_rules)
    generate_final_file(merged_rules)

if __name__ == "__main__":
    main()
