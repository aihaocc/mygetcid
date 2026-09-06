// api/index.js
const LOG_PASSWORD = process.env.LOG_PASSWORD || "admin123";

// ========== 工具函数 ========== 
function isAuth(request, password) {
  const cookie = request.headers.get("cookie") || "";
  return cookie.includes(`log_session=${password}`);
}

function loginPage() {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>日志登录</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#0f172a;color:#e2e8f0}
form{background:#1e293b;padding:2rem;border-radius:12px;width:min(90vw,360px)}h2{text-align:center;margin-bottom:1.5rem;font-size:1.25rem}
input{width:100%;padding:.75rem 1rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:1rem;margin-bottom:1rem;outline:none}
input:focus{border-color:#3b82f6}button{width:100%;padding:.75rem;border:none;border-radius:8px;background:#3b82f6;color:#fff;font-size:1rem;cursor:pointer;font-weight:600}
button:hover{background:#2563eb}.err{color:#f87171;text-align:center;margin-top:.75rem;font-size:.875rem}</style></head>
<body><form method="POST"><h2>🔐 日志系统登录</h2><input type="password" name="pwd" placeholder="请输入密码" autofocus required><button type="submit">登 录</button></form></body></html>`;
}

// ========== 主处理器 ==========
export default async function handler(request) {
  try {
    const baseUrl = `https://${request.headers.get('host') || 'localhost'}`;
    const url = new URL(request.url, baseUrl);
    const path = url.pathname;

    // ---------- 日志页面 POST 登录 ----------
    if (path === "/logs" && request.method === "POST") {
      const form = await request.formData();
      if (form.get("pwd") === LOG_PASSWORD) {
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/logs",
            "Set-Cookie": `log_session=${LOG_PASSWORD}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`
          }
        });
      }
      return new Response(loginPage().replace("</form>", '<p class="err">密码错误</p></form>'), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // ---------- 日志页面 GET（鉴权后展示） ----------
    if (path === "/logs") {
      if (!isAuth(request, LOG_PASSWORD)) {
        return new Response(loginPage(), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      // 无 KV 时返回提示页
      return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>日志</title></head>
<body style="font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;min-height:100vh">
<div style="text-align:center"><h1>📋 日志系统</h1><p style="margin-top:1rem;color:#94a3b8">当前未启用持久化存储，暂无日志数据。</p>
<a href="/" style="display:inline-block;margin-top:1.5rem;color:#3b82f6;text-decoration:none">← 返回首页</a></div></body></html>`, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // ---------- 根路由 POST（你的核心业务） ----------
    if (path === "/" && request.method === "POST") {
      const body = await request.json();
      // TODO: 替换为你的实际业务逻辑
      return Response.json({ success: true, received: body });
    }

    // ---------- 根路由 GET ----------
    if (path === "/") {
      return new Response("Service is running.", { status: 200 });
    }

    // ---------- 404 ----------
    return new Response("Not Found", { status: 404 });

  } catch (err) {
    console.error("HANDLER ERROR:", err);
    return Response.json(
      { error: "Internal Server Error", message: err.message },
      { status: 500 }
    );
  }
}

export const runtime = 'edge';
