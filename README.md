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
> 点击按钮即可复制对应地址，复制后按钮会显示「✅ 已复制」提示

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
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span id="raw-url" style="flex: 1; padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('raw-url', this)" style="padding: 6px 12px; border: none; border-radius: 4px; background: #2ea44f; color: white; cursor: pointer; font-size: 13px; white-space: nowrap;">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">通用加速</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span id="proxy1-url" style="flex: 1; padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">https://gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy1-url', this)" style="padding: 6px 12px; border: none; border-radius: 4px; background: #2ea44f; color: white; cursor: pointer; font-size: 13px; white-space: nowrap;">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">香港加速</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span id="proxy2-url" style="flex: 1; padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">https://hk.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy2-url', this)" style="padding: 6px 12px; border: none; border-radius: 4px; background: #2ea44f; color: white; cursor: pointer; font-size: 13px; white-space: nowrap;">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">CDN加速</td>
      <td style="padding: 8px; border-bottom: 1px solid #e1e4e8;">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span id="proxy3-url" style="flex: 1; padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">https://cdn.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy3-url', this)" style="padding: 6px 12px; border: none; border-radius: 4px; background: #2ea44f; color: white; cursor: pointer; font-size: 13px; white-space: nowrap;">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding: 8px;">边缘加速</td>
      <td style="padding: 8px;">
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
          <span id="proxy4-url" style="flex: 1; padding: 6px 8px; background: #f6f8fa; border-radius: 4px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace; font-size: 13px;">https://edgeone.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy4-url', this)" style="padding: 6px 12px; border: none; border-radius: 4px; background: #2ea44f; color: white; cursor: pointer; font-size: 13px; white-space: nowrap;">📋 复制</button>
        </div>
      </td>
    </tr>
  </tbody>
</table>

<!-- 复制功能脚本 - 优化版 -->
<script>
// 兼容 Clipboard API（现代浏览器）和 execCommand（降级方案）
async function copyToClipboard(elementId, button) {
  try {
    const text = document.getElementById(elementId).textContent.trim();
    const originalText = button.textContent;
    
    // 优先使用现代 Clipboard API
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);
    } else {
      // 降级方案：创建临时输入框
      const tempInput = document.createElement('input');
      tempInput.style.position = 'absolute';
      tempInput.style.opacity = '0';
      tempInput.value = text;
      document.body.appendChild(tempInput);
      tempInput.select();
      document.execCommand('copy');
      document.body.removeChild(tempInput);
    }
    
    // 复制成功提示
    button.textContent = "✅ 已复制";
    button.style.background = "#22863a"; // 加深绿色反馈
    setTimeout(() => {
      button.textContent = originalText;
      button.style.background = "#2ea44f"; // 恢复原背景色
    }, 1500);
    
  } catch (err) {
    // 复制失败提示
    const originalText = button.textContent;
    button.textContent = "❌ 复制失败";
    button.style.background = "#cb2431"; // 红色错误提示
    setTimeout(() => {
      button.textContent = originalText;
      button.style.background = "#2ea44f";
    }, 1500);
    console.error('复制失败:', err);
  }
}

// 修复 GitHub 可能的事件绑定问题
document.addEventListener('DOMContentLoaded', function() {
  // 重新绑定所有复制按钮的点击事件
  document.querySelectorAll('button[onclick^="copyToClipboard"]').forEach(btn => {
    const originalOnClick = btn.getAttribute('onclick');
    btn.removeAttribute('onclick');
    btn.addEventListener('click', function() {
      const elementId = this.previousElementSibling.id;
      copyToClipboard(elementId, this);
    });
  });
});
</script>

<!-- 全局样式重置（适配 GitHub 主题） -->
<style>
/* 适配 GitHub 浅色/深色模式 */
@media (prefers-color-scheme: dark) {
  .copy-text, 
  table td span,
  table thead th {
    background: #161b22 !important;
    color: #e6edf3 !important;
    border-color: #30363d !important;
  }
  table td, table th {
    border-color: #30363d !important;
  }
  button {
    background: #238636 !important;
  }
  button:hover {
    background: #2ea44f !important;
  }
}

/* 优化按钮 hover 效果 */
button:hover {
  background: #2c974b !important;
  transition: background-color 0.2s ease;
}

/* 修复表格在窄屏下的显示 */
table {
  width: 100%;
  border-collapse: collapse;
  overflow-x: auto;
  display: block;
}

/* 适配移动端 */
@media (max-width: 768px) {
  .copy-container, table td div {
    flex-direction: column;
    align-items: stretch !important;
  }
  button {
    width: 100%;
    margin-top: 4px;
  }
  table th {
    font-size: 12px;
  }
  table td span {
    font-size: 12px !important;
  }
}
</style>

## 工具核心功能
1. **多源规则下载**
   - 自动请求上游规则地址，过滤注释和空行
   - 处理网络超时、HTTP错误等异常情况
2. **格式智能转换**
   - 将 `0.0.0.0 域名` 等 Hosts 规则转为 AdGuard 标准格式 `||域名^`
3. **规则优化合并**
   - 数字后缀子域名泛化（如 `a36243.actonservice.com` → `a*.actonservice.com`）
   - 黑白名单冲突处理，白名单优先级高于黑名单
   - 相同域名规则保留带 `$important` 标记的高优先级规则
4. **自动化输出**
   - 规则去重并按域名排序
   - 生成带详细说明的标准化规则文件

## 使用说明
### 环境准备
```bash
# 克隆仓库
git clone https://github.com/guandasheng/AdGuardHome-Rule-Merger.git
cd AdGuardHome-Rule-Merger

# 安装依赖
pip install requests
