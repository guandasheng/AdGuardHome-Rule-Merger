# 上游规则链接列表（可根据需求增减）
UPSTREAM_RULES = [
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/lingeringsound/10007_auto/master/all",
    "https://pan.qzyun.net/f/LppT5/20251129.txt",
    "https://anti-ad.net/easylist.txt",
    "https://adrules.top/dns.txt",
]

# 输出文件路径（根目录）
OUTPUT_FILE = "merged_rules.txt"

# 规则过滤配置
SUPPORTED_RULE_TYPES = {
    "||": "域名屏蔽规则",
    "@||": "白名单规则",
    "127.0.0.1 ": "Hosts 屏蔽（IPV4）",
    "0.0.0.0 ": "Hosts 屏蔽（IPV4）",
    "::1 ": "Hosts 屏蔽（IPV6）",
}

# 需要剔除的规则前缀（AdGuard 专属/无效规则）
EXCLUDED_PREFIXES = (
    "!",          # 注释（自动忽略）
    "#",          # 注释（自动忽略）
    "//",         # 网页注释
    "@@||",       # 白名单规则（保留，此处用于过滤无效格式）
    "$",          # 单独的参数规则（无效）
    "||$",        # 无域名的规则（无效）
    "adguard_",   # AdGuard 专属配置
)

# 新增配置（仅保留223.5.5.5作为DNS解析服务器）
DNS_SERVERS = ["223.5.5.5", "223.6.6.6", "114.114.114.114"]  # 主DNS+备用DNS
RESOLVED_CACHE_FILE = "resolved_domains.json"  # 解析缓存文件
MYLIST_FILE = "mylist.txt"  # 人工审查规则文件
