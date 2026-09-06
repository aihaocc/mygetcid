import { kv } from '@vercel/kv';

// ========== 配置常量 ==========
const KV_BATCH_PREFIX = "batch_";
const KV_BLACKLIST_KEY = "BLACKLIST";
const CID_TOKEN_KEY = "cid_token_data";
const BAIDU_TOKEN_KEY = "baidu_ocr_token";

const BATCH_SIZE = 200;
const BATCH_FLUSH_SECONDS = 900; // 15min
const MAX_BATCH_READ = 100;

let logBatch = [];
let lastFlushTime = Date.now();
let flushing = false;

// 内存降级与缓存（注意：Vercel Edge 实例是短暂的，内存缓存不可保证跨请求持久）
let memoryLogs = [];
let useMemoryOnly = false;
let memoryBlacklist = [];

let memoryBaiduToken = null;
let memoryBaiduTokenExpiry = 0;
let memoryCidToken = null;
let memoryCidTokenExpiry = 0;

// ==================== 辅助函数 ====================
function isAuth(request, pwd) {
  const cookie = request.headers.get("cookie") || "";
  return cookie.split(";").some(c => c.trim() === "log_token=" + pwd);
}

function eI(t) {
  const e = t instanceof ArrayBuffer ? new Uint8Array(t) : new TextEncoder().encode(t);
  let n = "";
  for (const o of e) n += String.fromCharCode(o);
  return btoa(n).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

let tI = null;
async function yT() {
  if (!tI) {
    tI = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  }
  return tI;
}

async function c1(t, e) {
  const key = await yT();
  const jwk = await crypto.subtle.exportKey("jwk", key.publicKey);
  const header = eI(JSON.stringify({ alg: "ES256", typ: "dpop+jwt", jwk: jwk }));
  const payload = eI(JSON.stringify({
    htu: t,
    htm: e,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000)
  }));
  const unsigned = header + "." + payload;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    new TextEncoder().encode(unsigned)
  );
  return unsigned + "." + eI(signature);
}

function GenerateSessionId() {
  return "app_" + Math.random().toString(36).substring(2, 15);
}

async function safeParse(resp) {
  const text = await resp.text();
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

// ==================== Vercel KV 封装（替换 Workers KV） ====================
async function safeKvGet(key) {
  if (useMemoryOnly) return null;
  try {
    return await kv.get(key);
  } catch (err) {
    // 如果 KV 出错，可考虑降级到内存模式
    console.error("kv.get error", err);
    if (String(err?.message || "").toLowerCase().includes("limit")) useMemoryOnly = true;
    return null;
  }
}
async function safeKvPut(key, value) {
  if (useMemoryOnly) return;
  try {
    // kv.set 接受任意可序列化的值
    await kv.set(key, value);
  } catch (err) {
    console.error("kv.set error", err);
    if (String(err?.message || "").toLowerCase().includes("limit")) useMemoryOnly = true;
  }
}
async function safeKvDelete(key) {
  if (useMemoryOnly) return;
  try {
    await kv.del(key);
  } catch (err) {
    console.error("kv.del error", err);
  }
}
// 列表/前缀读取：尽量使用 kv.list，如果不存在则使用 scanIterator（兼容不同 SDK 版本）
async function safeKvList({ prefix = "", limit = MAX_BATCH_READ, cursor = undefined } = {}) {
  if (useMemoryOnly) return { keys: [] };
  try {
    if (typeof kv.list === "function") {
      // some @vercel/kv versions have kv.list
      const res = await kv.list({ prefix, limit, cursor });
      // ensure returned shape: { keys: [{ name }] , cursor }
      return res;
    } else if (typeof kv.scanIterator === "function") {
      // fallback: build keys from iterator
      const keys = [];
      for await (const k of kv.scanIterator({ prefix })) {
        keys.push({ name: k });
        if (keys.length >= limit) break;
      }
      return { keys, cursor: null };
    } else {
      // 最后兜底：没有列出能力，返回空
      return { keys: [] };
    }
  } catch (err) {
    console.error("safeKvList error", err);
    if (String(err?.message || "").toLowerCase().includes("limit")) useMemoryOnly = true;
    return { keys: [] };
  }
}

// ==================== Token 缓存（Vercel KV + 内存） ====================
async function getTokenData() {
  const now = Date.now();
  if (memoryCidToken && memoryCidTokenExpiry > now) return memoryCidToken;

  // 尝试从 KV 读
  let cached = null;
  try { cached = await safeKvGet(CID_TOKEN_KEY); } catch (_) { cached = null; }

  if (cached) {
    try {
      const data = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (data.expires_at && data.expires_at > now) {
        memoryCidToken = data;
        memoryCidTokenExpiry = data.expires_at;
        return data;
      }
    } catch (_) { /* ignore */ }
  }

  // 远程请求
  const tokenUrl = process.env.TOKEN_URL || "https://cidtoken.x2ray.cfd/";
  const res = await fetch(tokenUrl + "?getTokenData=1", { method: "GET", signal: AbortSignal.timeout?.(10000) || undefined });
  if (!res.ok) throw new Error(`Token 请求失败: ${res.status}`);
  const data = await res.json();
  if (!data || !data.access_token) throw new Error("无效的 Token 数据");

  const expiresIn = data.expires_in || 3600;
  const expiresAt = now + (expiresIn - 600) * 1000;
  const cacheData = { ...data, expires_at: expiresAt };

  // 写入 KV（字符串化）
  try { await safeKvPut(CID_TOKEN_KEY, JSON.stringify(cacheData)); } catch (_) {}
  memoryCidToken = cacheData;
  memoryCidTokenExpiry = expiresAt;
  return cacheData;
}

async function getBaiduToken(apiKey, secretKey) {
  const now = Date.now();
  if (memoryBaiduToken && memoryBaiduTokenExpiry > now) return memoryBaiduToken;

  let cached = null;
  try { cached = await safeKvGet(BAIDU_TOKEN_KEY); } catch (_) { cached = null; }

  if (cached) {
    try {
      const data = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (data.expires_at && data.expires_at > now) {
        memoryBaiduToken = data.access_token;
        memoryBaiduTokenExpiry = data.expires_at;
        return data.access_token;
      }
    } catch (_) {}
  }

  const tokenRes = await fetch(
    `https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id=${apiKey}&client_secret=${secretKey}`
  );
  if (!tokenRes.ok) throw new Error(`百度 Token 请求失败: ${tokenRes.status}`);
  const tokenData = await tokenRes.json();
  const token = tokenData.access_token;
  if (!token) throw new Error("百度 Token 响应缺少 access_token");

  const expiresIn = tokenData.expires_in || 2592000;
  const expiresAt = now + expiresIn * 1000;

  try {
    await safeKvPut(BAIDU_TOKEN_KEY, JSON.stringify({ access_token: token, expires_at: expiresAt }));
  } catch (_) {}
  memoryBaiduToken = token;
  memoryBaiduTokenExpiry = expiresAt;
  return token;
}

// ==================== 激活请求 ============
async function sendActivationRequest(IID) {
  if (!IID) throw new Error("missing IID");
  const dpop = await c1("/api/productActivation/validateIID", "POST");
  const sid = GenerateSessionId();
  const digits = Math.floor(IID.length / 9);

  const tokenJson = await getTokenData();
  if (!tokenJson || !tokenJson.access_token) {
    throw new Error("获取 AccessToken 失败，请检查网络或接口");
  }

  const res = await fetch("https://visualsupport.microsoft.com/api/productActivation/validateIID", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${tokenJson.id_token}`,
      "DPoP": dpop,
      "x-session-id": sid
    },
    body: JSON.stringify({
      IID: IID,
      ProductType: "windows",
      productGroup: "Windows",
      productName: "Windows 11",
      numberOfDigits: digits,
      Country: "CHN",
      Region: "APAC",
      InstalledDevices: 1,
      OverrideStatusCode: "MUL",
      InitialReasonCode: "45164"
    })
  });

  return {
    status: res.status,
    success: res.ok,
    data: await safeParse(res)
  };
}

// ==================== 时间格式 ============
function getFormatTime(offset = 8) {
  const now = new Date();
  const utc = now.getTime() + now.getTimezoneOffset() * 60000;
  const tz = new Date(utc + 3600000 * offset);
  return tz.toISOString().replace("T", " ").slice(0, 19);
}

// ==================== 自动降级 & 批量写入 ============
async function flushBatch() {
  if (flushing || logBatch.length === 0) return;
  flushing = true;
  try {
    if (useMemoryOnly) {
      memoryLogs.push(...logBatch);
      logBatch = [];
      lastFlushTime = Date.now();
      return;
    }

    const key = KV_BATCH_PREFIX + Date.now() + "_" + crypto.randomUUID();
    // 使用 KV 存储批次（字符串）
    await safeKvPut(key, JSON.stringify(logBatch));
    logBatch = [];
    lastFlushTime = Date.now();
  } finally {
    flushing = false;
  }
}

function needFlush() {
  if (logBatch.length >= BATCH_SIZE) return true;
  return (Date.now() - lastFlushTime) / 1000 > BATCH_FLUSH_SECONDS;
}

async function getAllLogs() {
  if (useMemoryOnly) {
    return [...memoryLogs].sort((a, b) => (b.time || "").localeCompare(a.time || ""));
  }

  try {
    const { keys } = await safeKvList({ prefix: KV_BATCH_PREFIX, limit: MAX_BATCH_READ });
    const all = [];
    for (const k of keys) {
      const val = await safeKvGet(k.name);
      if (!val) continue;
      try {
        const arr = typeof val === "string" ? JSON.parse(val) : val;
        if (Array.isArray(arr)) all.push(...arr);
      } catch (e) {}
    }
    return all.sort((a, b) => (b.time || "").localeCompare(a.time || ""));
  } catch (err) {
    console.error("getAllLogs error", err);
    return [...memoryLogs].sort((a, b) => (b.time || "").localeCompare(a.time || ""));
  }
}

async function deleteLogById(targetId) {
  if (!targetId) return false;
  if (useMemoryOnly) {
    const before = memoryLogs.length;
    memoryLogs = memoryLogs.filter(item => item.id !== targetId);
    return memoryLogs.length !== before;
  }
  const { keys } = await safeKvList({ prefix: KV_BATCH_PREFIX, limit: 100 });
  for (const k of keys) {
    const val = await safeKvGet(k.name);
    if (!val) continue;
    try {
      let arr = typeof val === "string" ? JSON.parse(val) : val;
      const filtered = arr.filter(item => item.id !== targetId);
      if (filtered.length !== arr.length) {
        if (filtered.length === 0) await safeKvDelete(k.name);
        else await safeKvPut(k.name, JSON.stringify(filtered));
        return true;
      }
    } catch (e) {}
  }
  return false;
}

async function clearAllLogs() {
  if (useMemoryOnly) {
    memoryLogs = [];
    return;
  }
  let cursor = undefined;
  do {
    const res = await safeKvList({ prefix: KV_BATCH_PREFIX, cursor });
    cursor = res.cursor;
    await Promise.all(res.keys.map(k => safeKvDelete(k.name)));
  } while (cursor);
}

// ==================== OCR / IID 提取 ============
function cleanOcrText(rawText) {
  let txt = rawText
    .replace(/test|jpg|png|jpeg/g, "")
    .replace(/[a-zA-Z\u4e00-\u9fa5]/g, "")
    .replace(/[^\d\s]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/\b(800|400)\d+\b/g, " ")
    .replace(/\b\d{1,6}\b/g, " ")
    .trim();
  return txt;
}

function extractIIDs(text) {
  const results = [];
  const filteredText = cleanOcrText(text);

  const pattern63 = /(?:\d{7}\s){8}\d{7}/g;
  const pattern54 = /(?:\d{6}\s){8}\d{6}/g;

  const m63 = filteredText.match(pattern63) || [];
  const m54 = filteredText.match(pattern54) || [];

  for (const s of m63) {
    const c = s.replace(/\s/g, "");
    if (c.length === 63) results.push(c);
  }
  for (const s of m54) {
    const c = s.replace(/\s/g, "");
    if (c.length === 54) results.push(c);
  }

  const longDigits = filteredText.match(/\d{54,63}/g) || [];
  longDigits.forEach(d => {
    if ([54, 63].includes(d.length)) results.push(d);
  });

  const pureAll = filteredText.replace(/\D/g, "");
  for (let i = 0; i <= pureAll.length - 63; i++) {
    const seg = pureAll.slice(i, i + 63);
    results.push(seg);
  }
  for (let i = 0; i <= pureAll.length - 54; i++) {
    const seg = pureAll.slice(i, i + 54);
    results.push(seg);
  }

  return [...new Set(results)].filter(x => [54, 63].includes(x.length));
}

async function baiduOCR(imageBase64, apiKey, secretKey) {
  const token = await getBaiduToken(apiKey, secretKey);
  const pureBase64 = imageBase64.replace(/^data:image\/\w+;base64,/, "");
  const ocrRes = await fetch(`https://aip.baidubce.com/rest/2.0/ocr/v1/general_basic?access_token=${token}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `image=${encodeURIComponent(pureBase64)}`
  });
  return ocrRes.json();
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 10240) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 10240));
  }
  return btoa(binary);
}

// ==================== 页面模板（保留原样） ============
function loginPage() {
  return `<!DOCTYPE html><meta charset="utf-8"><title>登录</title><style>body{display:grid;place-items:center;height:100vh;margin:0}.box{padding:24px;background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}input,button{width:100%;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #ddd}button{background:#0066cc;color:white;border:none;cursor:pointer}</style><div class="box"><h3>日志后台登录</h3><form method="post"><input type="password" name="pwd" required placeholder="密码"><button>登录</button></form></div>`;
}

function logPage(logs, page, totalPages, search, pageSize) {
  const start = (page - 1) * pageSize;
  const end = start + pageSize;
  const paginated = logs.slice(start, end);

  const rows = paginated.map(item => `
  <tr>
    <td>${item.time || ""}</td>
    <td style="font-family:monospace">${item.IID || ""}</td>
    <td>${item.ip || ""}</td>
    <td>${item.result && item.result.success ? "✅成功" : "❌失败"}</td>
    <td>
      <button onclick="del('${item.id}')" style="background:red;color:white;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;margin:0 2px">删除</button>
      <button onclick="searchSameIID('${encodeURIComponent(item.IID || "")}')" style="background:#6c757d;color:white;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;margin:0 2px">同IID</button>
      <button onclick="showDetail('${encodeURIComponent(JSON.stringify(item.result))}')" style="background:#0066cc;color:white;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;margin:0 2px">详情</button>
      <button onclick="blockIp('${item.ip}')" style="background:#d32f2f;color:white;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;margin:0 2px">拉黑IP</button>
      <button onclick="unblockIp('${item.ip}')" style="background:#388e3c;color:white;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;margin:0 2px">解封IP</button>
    </td>
  </tr>`).join("");

  const pages = [];
  for (let i = 1; i <= totalPages; i++) {
    pages.push(`<a href="?page=${i}&search=${encodeURIComponent(search)}" style="margin:0 5px;color:${page === i ? "red" : "#0066cc"}">${i}</a>`);
  }

  return `<!DOCTYPE html><meta charset="utf-8"><title>IID 激活日志</title>
<style>
body{margin:20px;font-family:system-ui;background:#fafafa}
.card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
.bar{display:flex;gap:10px;margin:10px 0}
input{flex:1;padding:8px;border-radius:6px;border:1px solid #ddd}
button{padding:8px 12px;border:none;border-radius:6px;color:white;cursor:pointer}
.red{background:red}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;border:1px solid #eee}
#detailModal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;align-items:center;justify-content:center}
#detailModal .modal-content{background:#fff;border-radius:8px;padding:20px;width:90%;max-width:800px;max-height:80vh;overflow:auto;position:relative}
#detailModal .modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
#detailModal .modal-header h3{margin:0;font-size:20px}
#detailModal .btn-group{display:flex;gap:10px}
#detailModal .btn-copy{background:#28a745;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:16px}
#detailModal .btn-close{background:#6c757d;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:16px}
#detailContent{background:#f8f9fa;padding:16px;border-radius:6px;white-space:pre-wrap;font-family:monospace;min-height:200px;max-height:50vh;overflow:auto}
.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#222;color:#fff;padding:10px 16px;border-radius:10px;opacity:0;transition:0.3s}
.toast.show{opacity:1;top:30px}
</style>

<div class="card">
  <h3>IID 激活日志 ${useMemoryOnly ? "(⚠️KV超限·内存模式)" : ""}</h3>
  <div class="bar">
    <input id="s" value="${search}" placeholder="搜索 IID">
    <button onclick="location.href='?search='+encodeURIComponent(document.getElementById('s').value)">搜索</button>
    <a href="/logs/clear"><button class="red">清空全部</button></a>
  </div>
  <div style="margin:10px 0">${pages.join("")}</div>
  <table>
    <tr><th>时间</th><th>IID</th><th>IP</th><th>状态</th><th>操作</th></tr>
    ${rows}
  </table>
</div>

<div id="detailModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>激活详情</h3>
      <div class="btn-group">
        <button class="btn-close" onclick="closeDetailModal()">关闭</button>
        <button class="btn-copy" id="copyJsonBtn" onclick="copyDetailJson()">复制JSON</button>
      </div>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const toast = msg => {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2000);
};

function searchSameIID(iid){
  if(!iid) return;
  location.href = "?search=" + decodeURIComponent(iid);
}

function showDetail(resultStr){
  try{
    const result = JSON.parse(decodeURIComponent(resultStr));
    $("#detailContent").textContent = JSON.stringify(result, null, 2);
    $("#detailModal").style.display = "flex";
  }catch(e){
    $("#detailContent").textContent = "解析失败：" + e;
    $("#detailModal").style.display = "flex";
  }
}

function closeDetailModal(){
  $("#detailModal").style.display = "none";
}

async function copyDetailJson(){
  const txt = $("#detailContent").textContent;
  if(!txt) { toast("暂无内容"); return; }
  try{
    await navigator.clipboard.writeText(txt);
    toast("已复制JSON");
  }catch(e){
    toast("复制失败，请手动复制");
  }
}

async function del(id){
  if(!confirm("确认删除？")) return;
  await fetch("/logs/delete",{method:"POST",body:id});
  location.reload();
}

async function blockIp(ip){
  if(!confirm('确认拉黑该IP：'+ip+'？')) return;
  await fetch("/logs/block-ip", {method:'POST', body:ip});
  toast('已拉黑');
}

async function unblockIp(ip){
  if(!confirm('确认解封该IP：'+ip+'？')) return;
  await fetch("/logs/unblock-ip", {method:'POST', body:ip});
  toast('已解封');
}
</script>`;
}

// ==================== IID 校验 ============
function checkBlock(block) {
    if (!/^\d+$/.test(block) || block.length < 2) return false;
    const check = Number(block.at(-1));
    let sum = 0;
    for (let i = 0; i < block.length - 1; i++) {
        const d = Number(block[i]);
        sum += i % 2 === 0 ? d : d * 2;
    }
    return sum % 7 === check;
}

function validateIID(iid) {
    if (!/^\d+$/.test(iid))
        return { valid: false, error: "not_numeric" };
    if (iid.length !== 54 && iid.length !== 63)
        return { valid: false, error: "invalid_length", length: iid.length };
    const blockSize = iid.length / 9;
    const failedBlocks = [];
    for (let i = 0; i < 9; i++) {
        const block = iid.slice(i * blockSize, (i + 1) * blockSize);
        if (!checkBlock(block)) {
            failedBlocks.push({ index: i + 1, value: block });
        }
    }
    return { valid: failedBlocks.length === 0, failedBlocks };
  }

function toolPage() {
  return `<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>获取确认 ID</title><style>body{font-family:system-ui;margin:40px auto;max-width:720px;padding:0 16px}textarea,button{box-sizing:border-box;width:100%;padding:10px;margin:8px 0}textarea{min-height:140px}button{color:#fff;background:#06c;border:0;border-radius:4px;cursor:pointer}pre{white-space:pre-wrap;background:#f5f5f5;padding:12px}</style><h1>获取确认 ID</h1><textarea id="iid" placeholder="输入 54 位或 63 位 IID"></textarea><button id="submit">提交</button><pre id="result"></pre><script>submit.onclick=async()=>{result.textContent="请求中...";try{const response=await fetch("/api/get-cid",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({IID:iid.value.trim()})});result.textContent=JSON.stringify(await response.json(),null,2)}catch(error){result.textContent=String(error)}}</script>`;
}

// ==================== Edge 函数入口 ============
export default async function (request) {
  const LOG_PASSWORD = process.env.LOG_PASSWORD || "";
  const PAGE_SIZE = parseInt(process.env.PAGE_SIZE || "20");
  const TIMEZONE = parseInt(process.env.TIMEZONE_OFFSET || "8");
  const BAIDU_API_KEY = process.env.BAIDU_API_KEY || "";
  const BAIDU_SECRET_KEY = process.env.BAIDU_SECRET_KEY || "";

  const url = new URL(request.url);
  const path = url.pathname;
  const clientIP = request.headers.get("x-forwarded-for")?.split(",")?.[0]?.trim() || request.headers.get("cf-connecting-ip") || "unknown";

  // ---------- 黑名单管理 ----------
  if (path === "/logs/block-ip" && request.method === "POST") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    const ip = await request.text();
    if (useMemoryOnly) {
      if (!memoryBlacklist.includes(ip)) memoryBlacklist.push(ip);
      return new Response("ok");
    }
    let list = await safeKvGet(KV_BLACKLIST_KEY).then(x => x ? JSON.parse(x) : []);
    if (!list.includes(ip)) {
      list.push(ip);
      await safeKvPut(KV_BLACKLIST_KEY, JSON.stringify(list));
    }
    return new Response("ok");
  }

  if (path === "/logs/unblock-ip" && request.method === "POST") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    const ip = await request.text();
    if (useMemoryOnly) {
      memoryBlacklist = memoryBlacklist.filter(i => i !== ip);
      return new Response("ok");
    }
    let list = await safeKvGet(KV_BLACKLIST_KEY).then(x => x ? JSON.parse(x) : []);
    list = list.filter(i => i !== ip);
    await safeKvPut(KV_BLACKLIST_KEY, JSON.stringify(list));
    return new Response("ok");
  }

  // ---------- IP 黑名单全局拦截 ----------
  let blacklist = [];
  if (useMemoryOnly) {
    blacklist = memoryBlacklist;
  } else {
    blacklist = await safeKvGet(KV_BLACKLIST_KEY).then(x => x ? JSON.parse(x) : []);
  }
  if (blacklist.includes(clientIP)) {
    return new Response("Forbidden", { status: 403 });
  }

  // ---------- 获取确认 ID（GET / POST） ----------
  if (path === "/api/get-cid" || path === "/api/get-cid/") {
    try {
      let IID = null;
      if (request.method === "GET") {
        IID = url.searchParams.get("IID");
      } else if (request.method === "POST") {
        const body = await request.json();
        IID = body.IID;
      } else {
        return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: { "Content-Type": "application/json" } });
      }

      if (!IID) return new Response(JSON.stringify({ error: "missing IID" }), { status: 400, headers: { "Content-Type": "application/json" } });

      const check = validateIID(IID);
      if (!check.valid) {
        return new Response(JSON.stringify({ error: "invalid IID", validate: check }), { status: 400, headers: { "Content-Type": "application/json" } });
      }

      const result = await sendActivationRequest(IID);

      // 记录日志到批次内存，按需 flush 到 KV
      logBatch.push({
        id: crypto.randomUUID(),
        time: getFormatTime(TIMEZONE),
        IID,
        ip: clientIP,
        result
      });
      if (needFlush()) await flushBatch();

      const response = new Response(JSON.stringify(result), { headers: { "Content-Type": "application/json" } });
      if (request.method === "GET") {
        response.headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
      }
      return response;
    } catch (err) {
      return new Response(JSON.stringify({ error: "request failed", detail: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  // ---------- 日志管理（展示 / 删除 / 清空） ----------
  if (path === "/logs/clear") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    await clearAllLogs();
    return Response.redirect("/logs", 302);
  }

  if (path === "/logs/delete" && request.method === "POST") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    const id = await request.text();
    await deleteLogById(id);
    return new Response("ok");
  }

  if (path === "/logs") {
    if (!LOG_PASSWORD) {
      return new Response("请设置 LOG_PASSWORD 环境变量", {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    if (request.method === "POST") {
      const form = await request.formData();
      const pwd = form.get("pwd");
      if (pwd === LOG_PASSWORD) {
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/logs",
            "Set-Cookie": "log_token=" + LOG_PASSWORD + "; Path=/logs; HttpOnly; Max-Age=86400; SameSite=Lax"
          }
        });
      }
    }

    if (!isAuth(request, LOG_PASSWORD)) {
      return new Response(loginPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 强制 flush 当前内存批次
    await flushBatch();
    const search = url.searchParams.get("search") || "";
    const page = parseInt(url.searchParams.get("page")) || 1;
    const logs = await getAllLogs();
    const filtered = search ? logs.filter(item => (item.IID || "").includes(search)) : logs;
    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    return new Response(logPage(filtered, page, totalPages, search, PAGE_SIZE), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }

  // ---------- OCR 接口 ----------
  if (path === "/api/ocr-iid" && request.method === "POST") {
    try {
      const form = await request.formData();
      const img = form.get("image");
      if (!img) return new Response(JSON.stringify({ error: "missing image" }), { headers: { "Content-Type": "application/json" } });
      const arrayBuffer = await img.arrayBuffer();
      const base64 = bufferToBase64(arrayBuffer);
      const ocr = await baiduOCR(`data:image/png;base64,${base64}`, BAIDU_API_KEY, BAIDU_SECRET_KEY);
      const text = ocr.words_result?.map(p => p.words).join("\n") || "";
      const iids = extractIIDs(text);
      if (!iids.length) return new Response(JSON.stringify({ error: "未找到IID", text }), { headers: { "Content-Type": "application/json" } });
      const iid = iids[0];
      const check = validateIID(iid);
      if (!check.valid) return new Response(JSON.stringify({ error: "invalid IID", validate: check }), { status: 400, headers: { "Content-Type": "application/json" } });
      const result = await sendActivationRequest(iid);

      logBatch.push({
        id: crypto.randomUUID(),
        time: getFormatTime(TIMEZONE),
        IID: iid,
        ip: clientIP,
        result: result
      });
      if (needFlush()) await flushBatch();

      return new Response(JSON.stringify(result), { headers: { "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: "ocr failed", detail: String(err) }), { headers: { "Content-Type": "application/json" } });
    }
  }

  if (path === "/api/ocr-only" && request.method === "POST") {
    try {
      const form = await request.formData();
      const img = form.get("image");
      const arrayBuffer = await img.arrayBuffer();
      const base64 = bufferToBase64(arrayBuffer);
      const ocr = await baiduOCR(`data:image/png;base64,${base64}`, BAIDU_API_KEY, BAIDU_SECRET_KEY);
      const text = ocr.words_result?.map(p => p.words).join("\n") || "";
      return new Response(JSON.stringify({ text }), { headers: { "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: "ocr failed", detail: String(err) }), { headers: { "Content-Type": "application/json" } });
    }
  }

  // ---------- 根路由 POST（旧逻辑） ----------
  if (request.method === "POST") {
    try {
      const body = await request.json();
      const IID = body.IID;
      if (!IID) return new Response(JSON.stringify({ error: "missing IID" }), { status: 400, headers: { "Content-Type": "application/json" } });
      const check = validateIID(IID);
      if (!check.valid) return new Response(JSON.stringify({ error: "invalid IID", validate: check }), { status: 400, headers: { "Content-Type": "application/json" } });

      const result = await sendActivationRequest(IID);

      logBatch.push({
        id: crypto.randomUUID(),
        time: getFormatTime(TIMEZONE),
        IID,
        ip: clientIP,
        result
      });
      if (needFlush()) await flushBatch();

      return new Response(JSON.stringify(result), { headers: { "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: "error", detail: String(err) }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  // 默认返回工具页面
  if (request.method === "GET") {
    return new Response(toolPage(), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }

  return new Response("Not found", { status: 404 });
}
