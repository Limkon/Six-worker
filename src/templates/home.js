/**
 * 文件名: src/templates/home.js
 * 说明: 存放主页/节点展示页相关的 HTML 模板
 * 修改: 移除了 Bootstrap CDN 依赖，使用内联轻量级 CSS
 * 调整了输入框和按钮的高度，使其更紧凑
 */

// 内联的轻量级 CSS，模拟 Bootstrap 核心样式
// 修改说明: 将 .form-control 和 .btn 的 padding 从 .375rem .75rem 调整为 .2rem .5rem 以降低高度
const INLINE_CSS = `
<style>
:root{--bs-primary:#0d6efd;--bs-secondary:#6c757d;--bs-info:#0dcaf0;--bs-body-bg:#fff;--bs-body-color:#212529}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background-color:var(--bs-body-bg);color:var(--bs-body-color);line-height:1.5;margin:0}
.container{max-width:900px;margin:0 auto;padding:1.5rem}
h1,h2,h3{margin-top:0;margin-bottom:.5rem;font-weight:500;line-height:1.2}
h1{font-size:calc(1.375rem + 1.5vw)} h2{font-size:calc(1.325rem + .9vw);margin-top:2rem}
hr{margin:1rem 0;color:inherit;border:0;border-top:1px solid;opacity:.25}
.mb-2{margin-bottom:.5rem!important} .mt-4{margin-top:1.5rem!important} .mb-4{margin-bottom:1.5rem!important}
.text-danger{color:#dc3545!important}
.input-group{position:relative;display:flex;flex-wrap:nowrap;width:100%}
.form-control{display:block;width:100%;padding:.2rem .5rem;font-size:1rem;font-weight:400;line-height:1.5;color:#212529;background-color:#fff;background-clip:padding-box;border:1px solid #ced4da;border-radius:.375rem;transition:border-color .15s ease-in-out,box-shadow .15s ease-in-out;min-width:100px}
.form-control[readonly]{background-color:#e9ecef;opacity:1}
.btn{display:inline-block;font-weight:400;line-height:1.5;color:#212529;text-align:center;text-decoration:none;vertical-align:middle;cursor:pointer;user-select:none;background-color:transparent;border:1px solid transparent;padding:.2rem .5rem;font-size:1rem;border-radius:.375rem;transition:color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out}
.btn-primary{color:#fff;background-color:#0d6efd;border-color:#0d6efd} .btn-primary:hover{background-color:#0b5ed7;border-color:#0a58ca}
.btn-secondary{color:#fff;background-color:#6c757d;border-color:#6c757d;border-top-left-radius:0;border-bottom-left-radius:0} .btn-secondary:hover{background-color:#5c636a;border-color:#565e64}
.btn-info{color:#000;background-color:#0dcaf0;border-color:#0dcaf0} .btn-info:hover{background-color:#31d2f2;border-color:#25cff2}
.input-group .form-control{border-top-right-radius:0;border-bottom-right-radius:0}
a.btn{margin-right:5px}
</style>`;

// 辅助函数：生成复制按钮 HTML
const copyBtn = (val) => `<div class="input-group mb-2"><input type="text" class="form-control" value="${val}" readonly><button class="btn btn-secondary" onclick="copyToClipboard('${val}')">复制</button></div>`;

export function getHomePageHtml(FileName, mixedTitle, isWorkersDev, subs, nodeDetailsHtml, managementPath) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>节点信息</title>${INLINE_CSS}</head><body><div class="container mt-4 mb-4">` +
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

// 辅助导出给 generators.js 或其他地方复用
export function getSectionHtml(title, content) {
    return `<h3>${title}</h3>${content}`;
}

export function getCopyBtnHtml(val) {
    return copyBtn(val);
}
