/**
 * 文件名: src/templates/admin.js
 * 说明: 前端模板文件，配合 admin.js 的文本格式验证进行更新
 * 修改: getAdminConfigHtml 移除了 Bootstrap CDN 依赖，使用内联轻量级 CSS
 */

export function getAdminConfigHtml(FileName, formHtml) {
    // 内联样式，替换原有的 Bootstrap 链接和 style 块
    const ADMIN_CSS = `
    <style>
    :root{--bs-primary:#0d6efd;--bs-secondary:#6c757d;--bs-info:#0dcaf0}
    body{font-family:system-ui,-apple-system,sans-serif;background-color:#f8f9fa;color:#212529;margin:0;line-height:1.5}
    .container{max-width:800px;margin:20px auto;background-color:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,.05)}
    h2{margin-top:0;margin-bottom:.5rem}
    code{color:#d63384}
    .form-text{font-size:0.875em;color:#6c757d;display:block;margin-top:.25rem}
    .env-hint{font-size:0.8em;color:#6c757d;margin-top:4px}
    .btn-group{display:flex;gap:10px;margin-top:1rem}
    .save-status{margin-left:15px;color:#666;align-self:center}
    /* 模拟 Bootstrap 表单样式 */
    .mb-3 { margin-bottom: 1rem; }
    label { display: inline-block; margin-bottom: .5rem; font-weight: 500; }
    .form-control { display: block; width: 100%; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; color: #212529; background-color: #fff; border: 1px solid #ced4da; border-radius: .375rem; box-sizing: border-box; transition: border-color .15s; }
    .form-control:focus { border-color: #86b7fe; outline: 0; box-shadow: 0 0 0 .25rem rgba(13,110,253,.25); }
    textarea.form-control { font-family: monospace; font-size: 0.9em; min-height: 100px; }
    /* 模拟 Bootstrap 按钮样式 */
    .btn { display: inline-block; font-weight: 400; line-height: 1.5; text-align: center; text-decoration: none; vertical-align: middle; cursor: pointer; user-select: none; border: 1px solid transparent; padding: .375rem .75rem; font-size: 1rem; border-radius: .375rem; transition: all .15s ease-in-out; }
    .btn-primary { color: #fff; background-color: #0d6efd; border-color: #0d6efd; } .btn-primary:hover { background-color: #0b5ed7; }
    .btn-secondary { color: #fff; background-color: #6c757d; border-color: #6c757d; } .btn-secondary:hover { background-color: #5c636a; }
    .btn-info { color: #000; background-color: #0dcaf0; border-color: #0dcaf0; } .btn-info:hover { background-color: #31d2f2; }
    .btn:disabled { opacity: .65; pointer-events: none; }
    </style>`;

    return `<!DOCTYPE html><html><head><title>配置管理</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${ADMIN_CSS}</head><body><div class="container">` +
    `<h2>${FileName} 配置设置</h2>` +
    '<p>在此页面修改的配置将保存在KV中, 优先级: <b>KV > 环境变量</b>。如果某项留空并保存, 则该项配置将回退到使用下级配置或默认值。</p>' +
    '<form id="config-form">' + formHtml + '<div class="btn-group"><button type="button" class="btn btn-secondary" onclick="goBack()">返回配置页</button><button type="button" class="btn btn-info" onclick="goBestIP()">在线优选IP</button><button type="submit" class="btn btn-primary" id="save-btn">保存所有配置</button><span class="save-status" id="saveStatus"></span></div></form>' +
    '<script>function goBack(){const e=window.location.pathname.substring(0,window.location.pathname.lastIndexOf("/"));window.location.href=e+"/"}function goBestIP(){window.location.href=window.location.pathname.replace("/edit","/bestip")}document.getElementById("config-form").addEventListener("submit",function(e){e.preventDefault();const t=document.getElementById("save-btn"),n=document.getElementById("saveStatus"),o=new FormData(this),a=o.get("BESTIP_SOURCES");if(a){const lines=a.split("\\n");for(let i=0;i<lines.length;i++){const line=lines[i].trim();if(!line)continue;const parts=line.split(/\\s+/);if(parts.length<2){return alert("保存失败: BestIP IP源 格式错误 (第"+(i+1)+"行)。\\n应为: 名称 网址"),n.textContent="保存出错: 格式错误",void 0}}}t.disabled=!0,t.textContent="保存中...",n.textContent="",fetch(window.location.href,{method:"POST",body:o}).then(e=>{if(e.ok){const o=(new Date).toLocaleString();n.textContent="保存成功 "+o,alert("保存成功！部分设置可能需要几秒钟生效。")}else return e.text().then(e=>Promise.reject(e))}).catch(e=>{n.textContent="保存出错: "+e}).finally(()=>{t.disabled=!1,t.textContent="保存所有配置"})});</script></body></html>';
}

// 下面的 getBestIPHtml 保持不变，因为它本身就不依赖 Bootstrap
export function getBestIPHtml(ipSourceOptions) {
    return `<!DOCTYPE html><html><head><title>Cloudflare IP优选</title><style>body{width:80%;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;padding:20px}.ip-list{background-color:#f5f5f5;padding:10px;border-radius:5px;max-height:400px;overflow-y:auto}.ip-item{margin:2px 0;font-family:monospace}.stats{background-color:#e3f2fd;padding:15px;border-radius:5px;margin:20px 0}.test-controls{margin-bottom:20px}.button-group{display:flex;gap:10px}.test-button,.save-button,.append-button,.edit-button,.back-button{background-color:#4CAF50;color:white;padding:15px 32px;text-align:center;text-decoration:none;display:inline-block;font-size:16px;cursor:pointer;border:none;border-radius:4px}.save-button{background-color:#2196F3}.append-button{background-color:#FF9800}.edit-button{background-color:#9C27B0}.back-button{background-color:#607D8B}.test-button:disabled,.save-button:disabled,.append-button:disabled{background-color:#cccccc;cursor:not-allowed}.message{padding:10px;margin:10px 0;border-radius:4px;display:none}.message.success{background-color:#d4edda;color:#155724}.message.error{background-color:#f8d7da;color:#721c24}.progress{width:100%;background-color:#f0f0f0;border-radius:5px;margin-top:10px}.progress-bar{width:0%;height:20px;background-color:#4CAF50;border-radius:5px;transition:width .3s;text-align:center;color:white;line-height:20px}.good-latency{color:#4CAF50;font-weight:700}.medium-latency{color:#FF9800;font-weight:700}.bad-latency{color:#f44336;font-weight:700}</style></head><body><h1>在线优选IP</h1><div class="test-controls"><div class="port-selector"style="margin-bottom:10px"><label for="ip-source-select">IP库：</label>` +
    `<select id="ip-source-select">${ipSourceOptions}</select> ` +
    `<label for="port-select">端口：</label><select id="port-select"><option value="443">443</option><option value="2053">2053</option><option value="2083">2083</option><option value="2087">2087</option><option value="2096">2096</option><option value="8443">8443</option></select>` +
    `</div><div class="button-group"><button class="test-button" id="test-btn">开始延迟测试</button><button class="save-button" id="save-btn" disabled>覆盖保存优选IP</button><button class="append-button" id="append-btn" disabled>追加保存优选IP</button><button class="edit-button" onclick="goEdit()">编辑优选列表</button><button class="back-button" onclick="goBack()">返回配置页</button></div></div><div class="stats"><p><strong>IP总数：</strong> <span id="ip-count">0</span></p><p><strong>测试进度：</strong> <span id="progress-text">未开始</span></p><div class="progress"><div class="progress-bar" id="progress-bar"></div></div></div><h2>IP列表 (结果已按延迟排序)</h2><div class="ip-list" id="ip-list">请选择端口和IP库，然后点击"开始延迟测试"</div><div id="message" class="message"></div>` +
    `<script>` +
    `let testResults=[],originalIPs=[];const testBtn=document.getElementById("test-btn"),saveBtn=document.getElementById("save-btn"),appendBtn=document.getElementById("append-btn"),ipList=document.getElementById("ip-list"),ipCount=document.getElementById("ip-count"),progressBar=document.getElementById("progress-bar"),progressText=document.getElementById("progress-text"),portSelect=document.getElementById("port-select"),ipSourceSelect=document.getElementById("ip-source-select");` +
    `function getBasePath() {return window.location.pathname.substring(0, window.location.pathname.lastIndexOf("/"));}` +
    `function goEdit(){window.location.href = getBasePath() + "/edit";}` +
    `function goBack(){window.location.href = getBasePath() + "/";}` +
    `async function testIP(e,t){const n=Date.now();try{const response = await fetch('?action=test&ip=' + e + '&port=' + t, {method:"GET",signal:AbortSignal.timeout(3e3)});if(response.ok){const data=await response.json();return data}}catch(err){console.error('Test failed for ' + e + ':' + t,err.name,err.message)}return null}` +
    `async function startTest(){testBtn.disabled=!0,testBtn.textContent="测试中...",saveBtn.disabled=!0,appendBtn.disabled=!0,ipList.innerHTML="正在加载IP列表...";const e=portSelect.value,t=ipSourceSelect.value;try{const n=(await(await fetch('?loadIPs=' + encodeURIComponent(t) + '&port=' + e)).json()).ips;originalIPs=n,ipCount.textContent=originalIPs.length,testResults=[],ipList.innerHTML="开始测试...",progressBar.style.width="0%",progressBar.textContent="",progressText.textContent="0/0";let o=0;const s=Math.min(32,originalIPs.length);let i=0;await new Promise(e=>{const t=()=>{if(i>=originalIPs.length){if(0==--o)return void e();return}const n=originalIPs[i++];testIP(n,portSelect.value).then(e=>{if(e&&e.colo!=="FAIL"){testResults.push(e)}progressBar.style.width = (100*(i/originalIPs.length)) + '%';progressBar.textContent = Math.round(100*(i/originalIPs.length)) + '%';progressText.textContent = i + '/' + originalIPs.length;t()})};for(let n=0;n<s;n++)o++,t()});testResults.sort((e,t)=>e.latency-t.latency),ipList.innerHTML=testResults.map(function(e) {var latencyClass = e.latency<100 ? "good-latency" : (e.latency<200 ? "medium-latency" : "bad-latency");return '<div class="ip-item ' + latencyClass + '">' + e.ip + ':' + e.port + '#' + e.colo + ' - ' + e.latency + 'ms</div>';}).join(""),saveBtn.disabled=0===testResults.length,appendBtn.disabled=0===testResults.length}catch(e){ipList.innerHTML="加载IP列表失败",console.error(e)}finally{testBtn.disabled=!1,testBtn.textContent="开始延迟测试"}}` +
    `async function saveIPs(e){const t=testResults.slice(16).map(function(e) { return e.ip + ':' + e.port + '#' + e.colo; });try{const n=(await(await fetch('?action=' + e,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:t})})).json());showMessage(n.message||n.error,n.success)}catch(e){showMessage("操作失败: "+e.message,!1)}}` +
    `function showMessage(e,t){const n=document.getElementById("message");n.textContent=e;n.className = 'message ' + (t ? 'success' : 'error');n.style.display="block",setTimeout(()=>{n.style.display="none"},3e3)}testBtn.addEventListener("click",startTest),saveBtn.addEventListener("click",()=>saveIPs("save"));appendBtn.addEventListener("click",()=>saveIPs("append"));` +
    `</script></body></html>`;
}
