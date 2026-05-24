#!/usr/bin/env python3
"""
User-Agent detection server.
Same URL, different UI based on who's visiting.
"""

import os
import json
import re
import socketserver
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("PORT", 8080))

# ── UA classification ─────────────────────────────────────────────────────────

def classify_ua(ua: str) -> str:
    ua_lower = ua.lower()
    if re.search(r'claude|anthropic', ua_lower):
        return "claude_agent"
    if re.search(r'gpt|openai|chatgpt', ua_lower):
        return "openai_agent"
    if re.search(r'gemini|bard|google-generativeai', ua_lower):
        return "google_agent"
    if re.search(r'curl/', ua_lower):
        return "curl"
    if re.search(r'python-requests|python-urllib|aiohttp|httpx', ua_lower):
        return "python_http"
    if re.search(r'wget', ua_lower):
        return "wget"
    if re.search(r'postman', ua_lower):
        return "postman"
    if re.search(r'bot|spider|crawl|scraper|slurp|facebookexternalhit', ua_lower):
        return "bot"
    if re.search(r'mozilla.*chrome|chromium', ua_lower):
        return "chrome"
    if re.search(r'mozilla.*firefox', ua_lower):
        return "firefox"
    if re.search(r'mozilla.*safari', ua_lower) and 'chrome' not in ua_lower:
        return "safari"
    if re.search(r'mozilla', ua_lower):
        return "browser"
    return "unknown"

UA_META = {
    "claude_agent": {"label": "Claude Agent",       "emoji": "🤖", "color": "#6c63ff"},
    "openai_agent": {"label": "OpenAI Agent",        "emoji": "🧠", "color": "#10a37f"},
    "google_agent": {"label": "Google AI Agent",     "emoji": "✨", "color": "#4285f4"},
    "curl":         {"label": "curl",                "emoji": "⚡", "color": "#f59e0b"},
    "python_http":  {"label": "Python HTTP client",  "emoji": "🐍", "color": "#3776ab"},
    "wget":         {"label": "wget",                "emoji": "📥", "color": "#f59e0b"},
    "postman":      {"label": "Postman",             "emoji": "📮", "color": "#ef5350"},
    "bot":          {"label": "Web Bot/Crawler",     "emoji": "🕷️", "color": "#9e9e9e"},
    "chrome":       {"label": "Chrome Browser",      "emoji": "🌐", "color": "#1a73e8"},
    "firefox":      {"label": "Firefox Browser",     "emoji": "🦊", "color": "#ff7139"},
    "safari":       {"label": "Safari Browser",      "emoji": "🧭", "color": "#006cff"},
    "browser":      {"label": "Web Browser",         "emoji": "🌍", "color": "#34a853"},
    "unknown":      {"label": "Unknown Client",      "emoji": "❓", "color": "#757575"},
}

# ── HTML builders ─────────────────────────────────────────────────────────────

CSS_RESET = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; min-height: 100vh; }
"""

def _data_block(ua: str, kind: str, meta: dict, extra: dict | None = None) -> dict:
    data = {
        "detected_at": datetime.utcnow().isoformat() + "Z",
        "user_agent": ua,
        "client_type": kind,
        "client_label": meta["label"],
        "message": f"Hello, {meta['label']}! This page adapts to who's visiting.",
    }
    if extra:
        data.update(extra)
    return data


def page_claude_agent(ua: str, kind: str, meta: dict) -> str:
    data = _data_block(ua, kind, meta, {
        "hint": "I'm serving you a machine-friendly response because I detected an AI agent.",
        "json_endpoint": "/api/ua",
        "capabilities": ["json_endpoint", "structured_data", "no_js_required"],
    })
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    color = meta["color"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>UA Detective — AI Agent View</title>
<style>
{CSS_RESET}
body {{ background: #0d1117; color: #c9d1d9; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; }}
.badge {{ background: {color}22; border: 1px solid {color}; border-radius: 8px; padding: 0.4rem 1rem; color: {color}; font-size: 0.85rem; letter-spacing: 1px; margin-bottom: 1.5rem; }}
h1 {{ color: {color}; font-size: 1.8rem; margin-bottom: 0.5rem; }}
p {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.95rem; }}
pre {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 1.5rem; font-size: 0.88rem; line-height: 1.6; width: 100%; max-width: 680px; overflow-x: auto; white-space: pre-wrap; }}
.key {{ color: #79c0ff; }}
.str {{ color: #a5d6ff; }}
.num {{ color: #79c0ff; }}
a {{ color: {color}; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.footer {{ margin-top: 2rem; font-size: 0.8rem; color: #484f58; }}
</style>
</head>
<body>
<div class="badge">{meta['emoji']} {meta['label'].upper()} DETECTED</div>
<h1>UA Detective</h1>
<p>Structured response — same URL, content tailored for AI agents.</p>
<pre id="json">{json_str}</pre>
<p class="footer">JSON endpoint also available at <a href="/api/ua">/api/ua</a></p>
</body>
</html>"""


def page_browser(ua: str, kind: str, meta: dict) -> str:
    color = meta["color"]
    label = meta["label"]
    emoji = meta["emoji"]
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UA Detective</title>
<style>
{CSS_RESET}
body {{ background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }}
.card {{ background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.12); max-width: 560px; width: 100%; overflow: hidden; }}
.hero {{ background: {color}; padding: 2.5rem 2rem; text-align: center; color: white; }}
.hero .icon {{ font-size: 4rem; margin-bottom: 0.5rem; }}
.hero h1 {{ font-size: 1.6rem; font-weight: 700; }}
.hero p {{ opacity: 0.85; margin-top: 0.4rem; font-size: 0.95rem; }}
.body {{ padding: 2rem; }}
.row {{ display: flex; justify-content: space-between; align-items: flex-start; padding: 0.75rem 0; border-bottom: 1px solid #f0f0f0; gap: 1rem; }}
.row:last-child {{ border-bottom: none; }}
.label {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; color: #9ca3af; flex-shrink: 0; }}
.value {{ font-size: 0.92rem; color: #1f2937; text-align: right; word-break: break-all; }}
.badge {{ display: inline-block; background: {color}18; color: {color}; border-radius: 6px; padding: 0.15rem 0.6rem; font-size: 0.8rem; font-weight: 600; }}
.api-hint {{ margin-top: 1.5rem; background: #f8fafc; border-left: 3px solid {color}; border-radius: 0 8px 8px 0; padding: 0.8rem 1rem; font-size: 0.83rem; color: #64748b; }}
.api-hint a {{ color: {color}; font-family: monospace; }}
</style>
</head>
<body>
<div class="card">
  <div class="hero">
    <div class="icon">{emoji}</div>
    <h1>Hello, {label}!</h1>
    <p>This page shows different UIs based on your User-Agent.</p>
  </div>
  <div class="body">
    <div class="row">
      <span class="label">Client type</span>
      <span class="value"><span class="badge">{label}</span></span>
    </div>
    <div class="row">
      <span class="label">User-Agent</span>
      <span class="value">{ua}</span>
    </div>
    <div class="row">
      <span class="label">Detected at</span>
      <span class="value">{now}</span>
    </div>
    <div class="api-hint">
      Want raw data? Try <a href="/api/ua">/api/ua</a> — returns JSON.
    </div>
  </div>
</div>
</body>
</html>"""


def page_cli(ua: str, kind: str, meta: dict) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    label = meta["label"]
    emoji = meta["emoji"]
    border = "─" * 52
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>UA Detective — CLI</title>
<style>
{CSS_RESET}
body {{ background: #1a1a1a; color: #d4d4d4; display: flex; align-items: center; justify-content: center; min-height: 100vh; font-family: 'Courier New', monospace; padding: 1rem; }}
.term {{ background: #0d0d0d; border: 1px solid #333; border-radius: 8px; padding: 2rem; max-width: 620px; width: 100%; }}
.green {{ color: #4ec9b0; }}
.yellow {{ color: #dcdcaa; }}
.cyan {{ color: #9cdcfe; }}
.dim {{ color: #555; }}
.prompt::before {{ content: '$ '; color: #4ec9b0; }}
pre {{ white-space: pre-wrap; line-height: 1.8; }}
</style>
</head>
<body>
<div class="term"><pre>
<span class="green">┌{border}┐</span>
<span class="green">│</span>  <span class="yellow">UA Detective</span> — CLI / Script Mode          <span class="green">│</span>
<span class="green">└{border}┘</span>

<span class="cyan">Client :</span> {emoji} {label}
<span class="cyan">UA     :</span> {ua}
<span class="cyan">Time   :</span> {now}

<span class="dim">Tip: GET /api/ua for JSON output</span>

<span class="prompt"></span>curl http://localhost:{PORT}/api/ua
</pre></div>
</body>
</html>"""


def page_bot(ua: str, kind: str, meta: dict) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>UA Detective — Bot</title>
<style>
{CSS_RESET}
body {{ background: #18181b; color: #a1a1aa; display: flex; align-items: center; justify-content: center; min-height: 100vh; font-family: system-ui; padding: 1rem; }}
.box {{ border: 1px solid #3f3f46; border-radius: 12px; padding: 2rem; max-width: 500px; width: 100%; text-align: center; }}
.icon {{ font-size: 3rem; margin-bottom: 1rem; }}
h1 {{ color: #f4f4f5; font-size: 1.3rem; margin-bottom: 0.5rem; }}
p {{ font-size: 0.88rem; line-height: 1.6; margin-top: 0.5rem; }}
.ua {{ font-family: monospace; font-size: 0.78rem; background: #27272a; border-radius: 6px; padding: 0.5rem 0.8rem; margin-top: 1rem; word-break: break-all; color: #71717a; }}
</style>
</head>
<body>
<div class="box">
  <div class="icon">🕷️</div>
  <h1>Bot/Crawler Detected</h1>
  <p>Client type: <strong>{meta['label']}</strong></p>
  <p>Detected at: {now}</p>
  <div class="ua">{ua}</div>
</div>
</body>
</html>"""


def render_page(ua: str) -> tuple[str, int]:
    kind = classify_ua(ua)
    meta = UA_META.get(kind, UA_META["unknown"])

    if kind in ("claude_agent", "openai_agent", "google_agent", "python_http"):
        html = page_claude_agent(ua, kind, meta)
    elif kind in ("curl", "wget", "postman"):
        html = page_cli(ua, kind, meta)
    elif kind == "bot":
        html = page_bot(ua, kind, meta)
    else:
        html = page_browser(ua, kind, meta)

    return html, 200


# ── Request handler ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        ua = self.headers.get("User-Agent", "-")
        kind = classify_ua(ua)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.command} {self.path} → {kind}  ({ua[:60]})")

    def do_GET(self):
        path = urlparse(self.path).path
        ua = self.headers.get("User-Agent", "")

        if path == "/api/ua":
            self._send_json(ua)
        elif path in ("/", "/index.html"):
            html, status = render_page(ua)
            self._send(html.encode(), "text/html; charset=utf-8", status)
        elif path == "/health":
            self._send(b"OK", "text/plain", 200)
        else:
            self._send(b"404 Not Found", "text/plain", 404)

    def _send_json(self, ua: str):
        kind = classify_ua(ua)
        meta = UA_META.get(kind, UA_META["unknown"])
        data = _data_block(ua, kind, meta, {
            "port": PORT,
            "endpoints": {"/": "HTML (UA-adaptive)", "/api/ua": "JSON", "/health": "health check"},
        })
        body = json.dumps(data, indent=2, ensure_ascii=False).encode()
        self._send(body, "application/json; charset=utf-8", 200)

    def _send(self, body: bytes, content_type: str, status: int):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.allow_reuse_address = True
        print(f"UA Detective running on http://localhost:{PORT}")
        print("Endpoints: /  (HTML)   /api/ua  (JSON)   /health  (ping)")
        print("─" * 50)
        httpd.serve_forever()
