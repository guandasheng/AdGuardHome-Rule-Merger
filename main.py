import requests
import re
from config import UPSTREAM_RULES, OUTPUT_FILE, SUPPORTED_RULE_TYPES, EXCLUDED_PREFIXES

def download_rule(url: str) -> list[str]:
    """下载单个上游规则，返回有效规则列表（过滤注释/空行）"""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # 抛出 HTTP 错误
        rules = response.text.split("\n")  # 按行分割
        # 过滤：空行、注释行（以 ! # // 开头）
        valid_rules = [
            rule.strip() for rule in rules
            if rule.strip() and not rule.strip().startswith(EXCLUDED_PREFIXES[:3])  # 排除注释
        ]
        print(f"✅ 成功下载 {url} | 有效规则数：{len(valid_rules)}")
        return valid_rules
    except Exception as e:
        print(f"❌ 下载失败 {url} | 错误：{str(e)}")
        return []

def convert_hosts_to_adguard(rule: str) -> str | None:
    """将 Hosts 规则（0.0.0.0 域名 / 127.0.0.1 域名）转换为 AdGuard 规则 ||域名^"""
    # 匹配 Hosts 格式：IP + 空格 + 域名（忽略后面的注释）
    hosts_pattern = r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]+)"
    match = re.match(hosts_pattern, rule)
    if match:
        domain = match.group(2)
        return f"||{domain}^"  # 转换为 AdGuard 标准屏蔽规则
    return None

def is_supported_rule(rule: str) -> bool:
    """判断规则是否为 AdGuard Home 支持的类型"""
    for prefix in SUPPORTED_RULE_TYPES.keys():
        if rule.startswith(prefix):
            return True
    return False

def extract_domain(rule: str) -> str | None:
    """从规则中提取核心域名（用于黑白名单冲突判断）"""
    # 处理 AdGuard 规则（||域名^ 或 @@||域名^）
    adguard_pattern = r"^(@@)?\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]+)\^"
    match = re.match(adguard_pattern, rule)
    if match:
        return match.group(2)  # 返回域名部分
    # 处理 Hosts 规则（已转换前，此处备用）
    hosts_pattern = r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]+)"
    match = re.match(hosts_pattern, rule)
    if match:
        return match.group(2)
    return None

def merge_rules(all_rules: list[str]) -> list[str]:
    """整合规则：格式转换、去重、黑白名单冲突处理"""
    rule_map = {}  # key: 域名, value: 规则（优先保留白名单）
    
    for rule in all_rules:
        # 1. 转换 Hosts 规则为 AdGuard 格式
        converted_rule = convert_hosts_to_adguard(rule)
        final_rule = converted_rule if converted_rule else rule
        
        # 2. 过滤不支持的规则
        if not is_supported_rule(final_rule):
            continue
        
        # 3. 提取域名，处理黑白名单冲突
        domain = extract_domain(final_rule)
        if not domain:
            continue  # 无法提取域名的规则跳过
        
        # 4. 优先级：白名单（@@开头）> 黑名单，相同域名保留白名单
        if domain in rule_map:
            # 若已有规则是白名单，跳过当前规则（无论黑白）
            if rule_map[domain].startswith("@@"):
                continue
            # 若当前规则是白名单，覆盖已有黑名单
            if final_rule.startswith("@@"):
                rule_map[domain] = final_rule
        else:
            # 新域名，直接添加
            rule_map[domain] = final_rule
    
    # 5. 去重后返回规则列表（按域名排序，便于查看）
    sorted_rules = sorted(rule_map.values(), key=lambda x: extract_domain(x) or x)
    return sorted_rules

def generate_final_file(rules: list[str]):
    """生成最终的合并规则文件，添加头部说明"""
    header = f"""# AdGuard Home 合并规则文件
# 自动生成：下载上游规则 → 格式转换 → 去重 → 冲突处理
# 上游规则来源：{chr(10).join([f"- {url}" for url in UPSTREAM_RULES])}
# 规则数量：{len(rules)}
# 维护者：guandasheng（GitHub 用户名）
# 定时更新：每 8 小时自动同步上游规则
# 说明：
# 1. Hosts 规则已转换为 AdGuard 格式（||域名^）
# 2. 已剔除 AdGuard Home 不支持的规则
# 3. 黑白名单冲突时，优先保留白名单规则（@@||域名^）
# 4. 所有规则已去重并按域名排序

"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(rules))
    
    print(f"\n🎉 合并完成！文件已保存至：{OUTPUT_FILE}")
    print(f"📊 最终规则数量：{len(rules)}")

def main():
    print("===== AdGuard Home 规则整合工具 =====")
    print(f"📥 正在下载 {len(UPSTREAM_RULES)} 个上游规则...")
    
    # 1. 下载所有上游规则
    all_rules = []
    for url in UPSTREAM_RULES:
        rules = download_rule(url)
        all_rules.extend(rules)
    
    print(f"\n📦 总下载规则数：{len(all_rules)}")
    print("🔧 正在整合规则（转换格式 + 去重 + 冲突处理）...")
    
    # 2. 整合规则
    merged_rules = merge_rules(all_rules)
    
    # 3. 生成最终文件
    generate_final_file(merged_rules)

if __name__ == "__main__":
    main()
