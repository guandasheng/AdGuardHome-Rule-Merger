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
> 点击地址即可自动复制到剪贴板
<table>
  <thead>
    <tr>
      <th style="width: 20%;">类型</th>
      <th style="width: 80%;">链接地址（点击复制）</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>原始地址</td>
      <td>
        <div class="copy-container">
          <span id="raw-url" class="copy-text">https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('raw-url')" class="copy-btn">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td>通用加速</td>
      <td>
        <div class="copy-container">
          <span id="proxy1-url" class="copy-text">https://gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy1-url')" class="copy-btn">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td>香港加速</td>
      <td>
        <div class="copy-container">
          <span id="proxy2-url" class="copy-text">https://hk.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy2-url')" class="copy-btn">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td>CDN加速</td>
      <td>
        <div class="copy-container">
          <span id="proxy3-url" class="copy-text">https://cdn.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy3-url')" class="copy-btn">📋 复制</button>
        </div>
      </td>
    </tr>
    <tr>
      <td>边缘加速</td>
      <td>
        <div class="copy-container">
          <span id="proxy4-url" class="copy-text">https://edgeone.gh-proxy.org/https://raw.githubusercontent.com/guandasheng/AdGuardHome-Rule-Merger/refs/heads/main/merged_rules.txt</span>
          <button onclick="copyToClipboard('proxy4-url')" class="copy-btn">📋 复制</button>
        </div>
      </td>
    </tr>
  </tbody>
</table>

<!-- 复制功能脚本 -->
<script>
function copyToClipboard(elementId) {
  // 获取文本内容
  const text = document.getElementById(elementId).textContent;
  // 创建临时输入框
  const tempInput = document.createElement('input');
  tempInput.value = text;
  document.body.appendChild(tempInput);
  // 选中并复制
  tempInput.select();
  document.execCommand('copy');
  // 移除临时输入框
  document.body.removeChild(tempInput);
  // 提示复制成功
  const btn = event.target;
  const originalText = btn.textContent;
  btn.textContent = "✅ 已复制";
  setTimeout(() => {
    btn.textContent = originalText;
  }, 1500);
}
</script>

<!-- 简单样式优化 -->
<style>
.copy-container {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.copy-text {
  flex: 1;
  padding: 4px 8px;
  background: #f5f5f5;
  border-radius: 4px;
  word-break: break-all;
  font-family: monospace;
}
.copy-btn {
  padding: 4px 12px;
  border: none;
  border-radius: 4px;
  background: #2ea44f;
  color: white;
  cursor: pointer;
  font-size: 14px;
}
.copy-btn:hover {
  background: #2c974b;
}
</style>
