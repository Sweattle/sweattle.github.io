// Password lock for the whole site (Cloudflare Pages Functions middleware).
//
// The password lives in the Cloudflare Pages secret SITE_PASSWORD — never in this repo.
// Visitors see a login page; a correct password sets a signed cookie for 30 days.
// Changing SITE_PASSWORD logs everyone out.

const COOKIE = "site_auth";
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const LOGIN_PATH = "/__login";
const LOGOUT_PATH = "/__logout";

export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);
  const password = env.SITE_PASSWORD;

  // Fail closed: no password configured means nobody gets in.
  if (!password) {
    return page("This site isn't set up yet.", { status: 503, showForm: false });
  }

  const token = await sign(password);

  if (url.pathname === LOGOUT_PATH) {
    return redirect("/", clearCookie());
  }

  if (url.pathname === LOGIN_PATH && request.method === "POST") {
    const form = await request.formData();
    const attempt = String(form.get("password") || "");
    const nextPath = safeNext(String(form.get("next") || "/"));
    if (await equal(await sign(attempt), token)) {
      return redirect(nextPath, setCookie(token));
    }
    await new Promise((r) => setTimeout(r, 600)); // slow down guessing
    return page("That password didn't work. Try again.", { status: 401, next: nextPath, error: true });
  }

  if (await equal(readCookie(request, COOKIE), token)) {
    const res = await next();
    const out = new Response(res.body, res);
    out.headers.set("X-Robots-Tag", "noindex, nofollow");
    out.headers.set("Cache-Control", "private, no-store");
    return out;
  }

  return page("", { status: 401, next: url.pathname + url.search });
}

/* ---------- helpers ---------- */

async function sign(value) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode("sweattle-site-lock-v1"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return "";
}

function setCookie(token) {
  return `${COOKIE}=${token}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`;
}
function clearCookie() {
  return `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function safeNext(p) {
  return p.startsWith("/") && !p.startsWith("//") && !p.startsWith(LOGIN_PATH) ? p : "/";
}

function redirect(location, cookie) {
  return new Response(null, {
    status: 303,
    headers: { Location: location, "Set-Cookie": cookie, "Cache-Control": "no-store" },
  });
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function page(message, { status, next = "/", error = false, showForm = true }) {
  const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>Travis Sweat</title>
<style>
  :root { --bg:#f5f5f7; --card:#fff; --text:#1d1d1f; --muted:#6e6e73; --line:#d2d2d7; --accent:#0066cc; --err:#d70015; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#000; --card:#1c1c1e; --text:#f5f5f7; --muted:#a1a1a6; --line:#38383a; --accent:#2997ff; --err:#ff6961; }
  }
  * { box-sizing: border-box; margin: 0; }
  html { font: 100%/1.5 -apple-system, BlinkMacSystemFont, system-ui, "Segoe UI Variable", "Segoe UI", "Helvetica Neue", Arial, sans-serif; }
  body { background: var(--bg); color: var(--text); min-height: 100vh; min-height: 100dvh;
         display: grid; place-items: center; padding: 1rem; -webkit-font-smoothing: antialiased; }
  main { width: 100%; max-width: 22rem; background: var(--card); border-radius: 1.375rem;
         padding: 2.5rem 2rem; text-align: center; }
  h1 { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.022em; line-height: 1.14; }
  p { color: var(--muted); margin-top: 0.5rem; font-size: 1.0625rem; letter-spacing: -0.008em; }
  p.err { color: var(--err); }
  form { margin-top: 1.75rem; display: grid; gap: 0.75rem; }
  input { font: inherit; font-size: 1.0625rem; padding: 0.75rem 1rem; border-radius: 0.75rem;
          border: 1px solid var(--line); background: transparent; color: var(--text); width: 100%; }
  input:focus { outline: 3px solid var(--accent); outline-offset: 1px; border-color: transparent; }
  button { font: inherit; font-size: 1.0625rem; font-weight: 500; padding: 0.75rem 1rem; border: 0;
           border-radius: 980px; background: var(--accent); color: #fff; cursor: pointer;
           transition: transform 100ms ease-out, filter 100ms ease-out; -webkit-tap-highlight-color: transparent; }
  button:active { transform: scale(0.97); filter: brightness(0.92); }
  @media (prefers-reduced-motion: reduce) { button:active { transform: none; } }
</style>
</head><body>
<main>
  <h1>Travis Sweat</h1>
  ${message ? `<p class="${error ? "err" : ""}" role="${error ? "alert" : "status"}">${escapeHtml(message)}</p>`
            : `<p>This site is private.</p>`}
  ${showForm ? `<form method="post" action="${LOGIN_PATH}">
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <input type="password" name="password" placeholder="Password" aria-label="Password"
           autocomplete="current-password" required autofocus>
    <button type="submit">Unlock</button>
  </form>` : ""}
</main>
</body></html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}
