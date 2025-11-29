# AdGuardHome-Rule-Merger
# AdGuard Home 规则自动整合工具

![Auto Update](https://github.com/guandasheng/AdGuardHome-Rule-Merger/actions/workflows/auto-update.yml/badge.svg)

一个 Python 脚本，用于自动下载多个上游广告过滤规则，进行格式转换、去重、黑白名单冲突处理，最终生成 AdGuard Home 可用的合并规则文件。

## 功能特点
1. **自动下载**：批量拉取配置中的上游规则链接
2. **格式转换**：将 `0.0.0.0 域名` / `127.0.0.1 域名` 等 Hosts 规则，转换为 AdGuard Home 标准规则 `||域名^`
3. **规则过滤**：剔除 AdGuard Home 不支持的规则（如 AdGuard 专属配置、无效规则）
4. **去重处理**：自动移除重复规则
5. **冲突解决**：若同一域名同时存在黑白名单规则（如 `||baidu.com^` 和 `@@||baidu.com^`），优先保留白名单
6. **定时更新**：每 8 小时自动同步上游规则并更新仓库（通过 GitHub Actions）
7. **排序优化**：最终规则按域名排序，便于查看和维护

## 快速使用
### 1. 环境准备
```bash
# 克隆仓库（你的 GitHub 仓库地址）
git clone https://github.com/guandasheng/AdGuardHome-Rule-Merger.git
cd AdGuardHome-Rule-Merger

# 安装依赖（仅需 requests）
pip install requests
