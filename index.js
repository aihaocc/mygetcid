import { kv } from '@vercel/kv';

// ==================== 配置 ====================
const LOG_PASSWORD = process.env.LOG_PASSWORD;
const PAGE_SIZE = parseInt(process.env.PAGE_SIZE) || 20;
const TIMEZONE = parseInt(process.env.TIMEZONE_OFFSET) || 8;
const BAIDU_API_KEY = process.env.BAIDU_API_KEY || "";
const BAIDU_SECRET_KEY = process.env.BAIDU_SECRET_KEY || "";

// Redis Keys
const KEY_LOGS = "iid_logs";
const KEY_BLACKLIST = "ip_blacklist";
const KEY_BAIDU_TOKEN = "baidu_ocr_token";
const KEY_CID_TOKEN = "cid_token_data";

// ==================== 辅助函数 ====================
function isAuth(req, pwd) {
  const cookie = req.headers.get("cookie") || "";
  return cookie.split(";").some(c => c.trim() === "log_token=" + pwd);
}

function getFormatTime(offset = 8) {
  const now = new Date();
  const utc = now.getTime() + now.getTimezoneOffset() * 60000;
  const tz = new Date(utc + 3600000 * offset);
  return tz.toISOString().replace("T", " ").slice(0, 19);
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
    htu: t, htm: e, jti: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000)
  }));
  const unsigned = header + "." + payload;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(unsigned)
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

// ==================== Token 缓存 (Redis 版) ====================
async function getTokenData() {
  // 1. Redis 缓存
  const cached = await kv.get(KEY_CID_TOKEN);
  if (cached && cached.expires_at > Date.now()) return cached;

  // 2. 请求远程
  const res = await fetch("https://api.aihao.cc/v1/api.php?getTokenData=1", {
    method: "GET", signal: AbortSignal.timeout(10000)
  });
  if (!res.ok) throw new Error(`Token 请求失败: ${res.status}`);
  const data = await res.json();
  if (!data?.access_token) throw new Error("无效的 Token 数据");

  const expiresIn = data.expires_in || 3600;
  const expiresAt = Date.now() + (expiresIn - 600) * 1000;
  const cacheData = { ...data, expires_at: expiresAt };

  // 3. 写入 Redis (带过期时间)
  await kv.set(KEY_CID_TOKEN, cacheData, { ex: expiresIn - 600 });
  return cacheData;
}

async function getBaiduToken(apiKey, secretKey) {
  const cached = await kv.get(KEY_BAIDU_TOKEN);
  if (cached && cached.expires_at > Date.now()) return cached.access_token;

  const tokenRes = await fetch(
    `https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id=${apiKey}&client_secret=${secretKey}`
  );
  if (!tokenRes.ok) throw new Error(`百度 Token 请求失败: ${tokenRes.status}`);
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) throw new Error("百度 Token 响应缺少 access_token");

  const expiresIn = tokenData.expires_in || 2592000;
  const expiresAt = Date.now() + expiresIn * 1000;

  await kv.set(KEY_BAIDU_TOKEN, { access_token: tokenData.access_token, expires_at: expiresAt }, { ex: expiresIn });
  return tokenData.access_token;
}

// ==================== 激活请求 ====================
async function sendActivationRequest(IID) {
  if (!IID) throw new Error("missing IID");
  const dpop = await c1("/api/productActivation/validateIID", "POST");
  const sid = GenerateSessionId();
  const digits = Math.floor(IID.length / 9);
  const tokenJson = await getTokenData();

  const res = await fetch("https://visualsupport.microsoft.com/api/productActivation/validateIID", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${tokenJson.id_token}`,
      "DPoP": dpop,
      "x-session-id": sid
    },
    body: JSON.stringify({
      IID, ProductType: "windows", productGroup: "Windows", productName: "Windows 11",
      numberOfDigits: digits, Country: "CHN", Region: "APAC", InstalledDevices: 1,
      OverrideStatusCode: "MUL", InitialReasonCode: "45164"
    })
  });

  return { status: res.status, success: res.ok, data: await safeParse(res) };
}

// ==================== 日志管理 (Redis List 版) ====================
async function addLog(entry) {
  // LPUSH 保证最新在前，LTRIM 限制最多保留 5000 条防止内存溢出
  await kv.lpush(KEY_LOGS, entry);
  await kv.ltrim(KEY_LOGS, 0, 4999);
}

async function getAllLogs() {
  return await kv.lrange(KEY_LOGS, 0, -1);
}

async function deleteLogById(targetId) {
  const logs = await kv.lrange(KEY_LOGS, 0, -1);
  const filtered = logs.filter(item => item.id !== targetId);
  if (filtered.length === logs.length) return false;
  
  // 原子替换整个列表
  await kv.del(KEY_LOGS);
  if (filtered.length > 0) {
    // 反转后 RPUSH 保持顺序一致
    for (const item of filtered.reverse()) {
      await kv.rpush(KEY_LOGS, item);
    }
  }
  return true;
}

async function clearAllLogs() {
  await kv.del(KEY_LOGS);
}

// ==================== 黑名单 (Redis Set 版) ====================
async function isBlocked(ip) {
  return await kv.sismember(KEY_BLACKLIST, ip);
}
async function blockIp(ip) { await kv.sadd(KEY_BLACKLIST, ip); }
async function unblockIp(ip) { await kv.srem(KEY_BLACKLIST, ip); }

// ==================== OCR & IID 校验 ====================
function cleanOcrText(rawText) {
  return rawText.replace(/test|jpg|png|jpeg/g, "").replace(/[a-zA-Z\u4e00-\u9fa5]/g, "")
    .replace(/[^\d\s]/g, " ").replace(/\s+/g, " ").replace(/\b(800|400)\d+\b/g, " ")
    .replace(/\b\d{1,6}\b/g, " ").trim();
}

function extractIIDs(text) {
  const results = [];
  const filteredText = cleanOcrText(text);
  const pattern63 = /(?:\d{7}\s){8}\d{7}/g;
  const pattern54 = /(?:\d{6}\s){8}\d{6}/g;
  (filteredText.match(pattern63) || []).forEach(s => { const c = s.replace(/\s/g, ""); if (c.length === 63) results.push(c); });
  (filteredText.match(pattern54) || []).forEach(s => { const c = s.replace(/\s/g, ""); if (c.length === 54) results.push(c); });
  (filteredText.match(/\d{54,63}/g) || []).forEach(d => { if ([54, 63].includes(d.length)) results.push(d); });
  const pureAll = filteredText.replace(/\D/g, "");
  for (let i = 0; i <= pureAll.length - 63; i++) results.push(pureAll.slice(i, i + 63));
  for (let i = 0; i <= pureAll.length - 54; i++) results.push(pureAll.slice(i, i + 54));
  return [...new Set(results)].filter(x => [54, 63].includes(x.length));
}

async function baiduOCR(imageBase64, apiKey, secretKey) {
  const token = await getBaiduToken(apiKey, secretKey);
  const pureBase64 = imageBase64.replace(/^data:image\/\w+;base64,/, "");
  const ocrRes = await fetch(`https://aip.baidubce.com/rest/2.0/ocr/v1/general_basic?access_token=${token}`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `image=${encodeURIComponent(pureBase64)}`
  });
  return ocrRes.json();
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 10240) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 10240));
  }
  return btoa(binary);
}

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
  if (!/^\d+$/.test(iid)) return { valid: false, error: "not_numeric" };
  if (iid.length !== 54 && iid.length !== 63) return { valid: false, error: "invalid_length", length: iid.length };
  const blockSize = iid.length / 9;
  const failedBlocks = [];
  for (let i = 0; i < 9; i++) {
    const block = iid.slice(i * blockSize, (i + 1) * blockSize);
    if (!checkBlock(block)) failedBlocks.push({ index: i + 1, value: block });
  }
  return { valid: failedBlocks.length === 0, failedBlocks };
}

// ==================== HTML 页面模板 (保持不变) ====================
// 注意：loginPage(), logPage(), toolPage() 三个函数体与原代码完全相同
// 为节省篇幅此处省略，请直接复制原代码中的这三个函数
function loginPage() { /* ... 原代码不变 ... */ }
function logPage(logs, page, totalPages, search, pageSize) { /* ... 原代码不变 ... */ }
function toolPage() { /* ... 原代码不变 ... */ }


// ==================== Vercel Serverless 入口 ====================
export default async function handler(request) {
  // 兼容 Vercel rewrite 导致的相对路径
  const baseUrl = `https://${request.headers.get('host') || 'localhost'}`;
  const url = new URL(request.url, baseUrl);
  
  const path = url.pathname;
  const clientIP = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";

  // ---------- 黑名单拦截 ----------
  if (await isBlocked(clientIP)) {
    return new Response("Forbidden", { status: 403 });
  }

  // ---------- 黑名单管理 API ----------
  if (path === "/logs/block-ip") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    const ip = await request.text();
    await blockIp(ip);
    return new Response("ok");
  }
  if (path === "/logs/unblock-ip") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    const ip = await request.text();
    await unblockIp(ip);
    return new Response("ok");
  }

  // ---------- 获取确认 ID API ----------
  if (path === "/api/get-cid" || path === "/api/get-cid/") {
    try {
      let IID = null;
      if (request.method === "GET") {
        IID = url.searchParams.get("IID");
      } else if (request.method === "POST") {
        const body = await request.json();
        IID = body.IID;
      } else {
        return Response.json({ error: "Method not allowed" }, { status: 405 });
      }
      if (!IID) return Response.json({ error: "missing IID" }, { status: 400 });
      const check = validateIID(IID);
      if (!check.valid) return Response.json({ error: "invalid IID", validate: check }, { status: 400 });

      const result = await sendActivationRequest(IID);
      await addLog({ id: crypto.randomUUID(), time: getFormatTime(TIMEZONE), IID, ip: clientIP, result });

      const response = Response.json(result);
      if (request.method === "GET") response.headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
      return response;
    } catch (err) {
      return Response.json({ error: "request failed", detail: err.message }, { status: 500 });
    }
  }

  // ---------- 日志管理 ----------
  if (path === "/logs/clear") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    await clearAllLogs();
    return Response.redirect("/logs", 302);
  }
  if (path === "/logs/delete") {
    if (!isAuth(request, LOG_PASSWORD)) return new Response("403", { status: 403 });
    const id = await request.text();
    await deleteLogById(id);
    return new Response("ok");
  }
  if (path === "/logs") {
    if (!LOG_PASSWORD) return new Response("请设置 LOG_PASSWORD 环境变量", { headers: { "Content-Type": "text/html; charset=utf-8" } });
    if (request.method === "POST") {
      const form = await request.formData();
      if (form.get("pwd") === LOG_PASSWORD) {
        return new Response(null, {
          status: 302,
          headers: { "Location": "/logs", "Set-Cookie": `log_token=${LOG_PASSWORD}; Path=/logs; HttpOnly; Max-Age=86400; SameSite=Lax` }
        });
      }
    }
    if (!isAuth(request, LOG_PASSWORD)) return new Response(loginPage(), { headers: { "Content-Type": "text/html; charset=utf-8" } });

    const search = url.searchParams.get("search") || "";
    const page = parseInt(url.searchParams.get("page")) || 1;
    const logs = await getAllLogs();
    const filtered = search ? logs.filter(item => (item.IID || "").includes(search)) : logs;
    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    return new Response(logPage(filtered, page, totalPages, search, PAGE_SIZE), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  // ---------- OCR 接口 ----------
  if (path === "/api/ocr-iid" && request.method === "POST") {
    try {
      const form = await request.formData();
      const img = form.get("image");
      if (!img) return Response.json({ error: "missing image" });
      const base64 = bufferToBase64(await img.arrayBuffer());
      const ocr = await baiduOCR(`data:image/png;base64,${base64}`, BAIDU_API_KEY, BAIDU_SECRET_KEY);
      const text = ocr.words_result?.map(p => p.words).join("\n") || "";
      const iids = extractIIDs(text);
      if (!iids.length) return Response.json({ error: "未找到IID", text });
      const iid = iids[0];
      const check = validateIID(iid);
      if (!check.valid) return Response.json({ error: "invalid IID", validate: check }, { status: 400 });
      const result = await sendActivationRequest(iid);
      await addLog({ id: crypto.randomUUID(), time: getFormatTime(TIMEZONE), IID: iid, ip: clientIP, result });
      return Response.json(result);
    } catch (err) {
      return Response.json({ error: "ocr failed", detail: err + "" });
    }
  }
  if (path === "/api/ocr-only" && request.method === "POST") {
    try {
      const form = await request.formData();
      const img = form.get("image");
      const base64 = bufferToBase64(await img.arrayBuffer());
      const ocr = await baiduOCR(`data:image/png;base64,${base64}`, BAIDU_API_KEY, BAIDU_SECRET_KEY);
      const text = ocr.words_result?.map(p => p.words).join("\n") || "";
      return Response.json({ text });
    } catch (err) {
      return Response.json({ error: "ocr failed", detail: err + "" });
    }
  }

  // ---------- GET 工具页 / POST 根路由激活 ----------
  if (request.method === "GET") {
    return new Response(toolPage(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  try {
    const body = await request.json();
    const IID = body.IID;
    if (!IID) return Response.json({ error: "missing IID" }, { status: 400 });
    const check = validateIID(IID);
    if (!check.valid) return Response.json({ error: "invalid IID", validate: check }, { status: 400 });
    const result = await sendActivationRequest(IID);
    await addLog({ id: crypto.randomUUID(), time: getFormatTime(TIMEZONE), IID, ip: clientIP, result });
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: "error", detail: err + "" }, { status: 500 });
  }
}

// Vercel Edge Runtime 配置（可选，若用 Node Runtime 则删除此行）
// export const runtime = 'edge';
