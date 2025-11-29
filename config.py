# 上游规则链接列表（可根据需求增减）
UPSTREAM_RULES = [
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/main/rule/adgh.txt",
    "https://pan.qzyun.net/f/ERZip/Black.txt",
]

# 输出文件路径（根目录）
OUTPUT_FILE = "merged_rules.txt"

# 规则过滤配置
SUPPORTED_RULE_TYPES = {
    "||": "域名屏蔽规则",
    "@||": "白名单规则",
    "127.0.0.1 ": "Hosts 屏蔽（IPV4）",
    "0.0.0.1 ": "Hosts 屏蔽（IPV4）",
    "::1 ": "Hosts 屏蔽（IPV6）",
}

# 需要剔除的规则前缀（AdGuard 专属/无效规则）
EXCLUDED_PREFIXES = [
    "!",          # 注释（自动忽略）
    "#",          # 注释（自动忽略）
    "@@||",       # 白名单规则（保留，此处仅作为对比）
    "$",          # 单独的参数规则（无效）
    "||$",        # 无域名的规则（无效）
    "adguard_",   # AdGuard 专属配置
    "//",         # 网页注释
]
