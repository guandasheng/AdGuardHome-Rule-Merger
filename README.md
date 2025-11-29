# AdGuardHome-Rule-Merger
AdGuard Home 规则自动合并工具，可批量下载上游规则并完成格式转换、泛化合并、冲突处理，最终生成标准化的过滤规则文件。

## 项目数据概览
| 指标 | 信息 |
| ---- | ---- |
| 规则更新时间 | ![Last Updated](https://img.shields.io/github/last-commit/guandasheng/AdGuardHome-Rule-Merger?label=最后更新时间) |
| 规则总数 | ![Rule Count](https://img.shields.io/badge/dynamic/text?url=https%3A%2F%2Fraw.githubusercontent.com%2Fguandasheng%2FAdGuardHome-Rule-Merger%2Fmain%2Fmerged_rules.txt&query=%2F%23%20%E8%A7%84%E5%88%99%E6%95%B0%E9%87%8F%EF%BC%9A(\d+)&label=有效规则数) |
| 仓库星标 | ![Stars](https://img.shields.io/github/stars/guandasheng/AdGuardHome-Rule-Merger?style=social) |
| 访问人数 | ![Visitors](https://visitor-badge.laobi.icu/badge?page_id=guandasheng.AdGuardHome-Rule-Merger) |

## 合并规则文件
### 规则文件地址
> 可直接选中以下地址复制使用

<table>
  <thead>
    <tr>
      <th style="width: 20%; padding: 8px; text-align: left; background: #f6f8fa; border-bottom: 1px solid #e1e4e8;">类型</th>
      <th style="width: 80%; padding: 8px; text-align: left; background: #f6f8fa; border-bottom: 1px solid #e1e4e8;">链接地址</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">原始地址</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <code style="padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">
          https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt
        </code>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">通用加速</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <code style="padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">
          https://gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt
        </code>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">香港加速</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <code style="padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">
          https://hk.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt
        </code>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">CDN加速</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <code style="padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">
          https://cdn.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt
        </code>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px;">边缘加速</td>
      <td style="padding: 8px;">
        <code style="padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">
          https://edgeone.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt
        </code>
      </td>
    </tr>
  </tbody>
</table>

<!-- 适配 GitHub 深色模式 -->
<style>
@media (prefers-color-scheme: dark) {
  table td code,
  table thead th {
    background: #161b22 !important;
    color: #e6edf3 !important;
    border-color: #30363d !important;
  }
  table td, table th {
    border-color: #30363d !important;
  }
}

/* 优化表格响应式显示 */
table {
  width: 100%;
  border-collapse: collapse;
  overflow-x: auto;
  display: block;
}

/* 移动端适配 */
@media (max-width: 768px) {
  table th {
    font-size: 12px;
  }
  table td code {
    font-size: 12px !important;
  }
}
</style>

