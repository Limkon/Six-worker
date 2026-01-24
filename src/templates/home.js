/**
 * 文件名: src/templates/home.js
 * 说明: 存放主页/节点展示页相关的 HTML 模板
 */

// 辅助函数：生成复制按钮 HTML
const copyBtn = (val) => `<div class="input-group mb-2"><input type="text" class="form-control" value="${val}" readonly><button class="btn btn-secondary" onclick="copyToClipboard('${val}')">复制</button></div>`;

export function getHomePageHtml(FileName, mixedTitle, isWorkersDev, subs, nodeDetailsHtml, managementPath) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>节点信息</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><style>.container{max-width:900px} .input-group{flex-wrap:nowrap} .form-control{min-width:100px}</style></head><body><div class="container mt-4 mb-4">` +
    `<h1>${FileName} 代理节点管理</h1><hr>` +
    `<h2>${mixedTitle}</h2>` +
    `<p class="text-danger"><b>(注意: 订阅链接已包含访问密钥，请勿泄露)</b></p>` +
    (isWorkersDev ? `<b>所有协议 (含无TLS):</b>${copyBtn(subs.all)}` : '') +
    `<b>通用订阅 (推荐 TLS):</b>${copyBtn(subs.all_tls)}` +
    `<b>Clash-Meta (TLS):</b>${copyBtn(subs.all_clash_tls)}` +
    `<b>Sing-Box (TLS):</b>${copyBtn(subs.all_sb_tls)}` +
    `<hr>` +
    `<h2>管理工具</h2>` +
    `<div class="mb-2"><a href="${managementPath}/edit" class="btn btn-primary">编辑配置</a> <a href="${managementPath}/bestip" class="btn btn-info">在线优选IP</a></div>` +
    `<hr>` +
    `<h2>节点详情</h2>` +
    nodeDetailsHtml +
    `</div><script>function copyToClipboard(text){navigator.clipboard.writeText(text).then(function(){alert("已复制")}, function(err){alert("复制失败")});}</script></body></html>`;
}

// 辅助导出给 generators.js 或其他地方复用（如果需要）
export function getSectionHtml(title, content) {
    return `<h3>${title}</h3>${content}`;
}

export function getCopyBtnHtml(val) {
    return copyBtn(val);
}
