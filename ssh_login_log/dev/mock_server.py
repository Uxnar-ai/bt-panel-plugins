# -*- coding: utf-8 -*-
"""本地模拟宝塔面板插件接口，用于在浏览器里验证前端。

用法：python dev/mock_server.py [port]
访问：http://127.0.0.1:8891/           浅色
      http://127.0.0.1:8891/?theme=dark 深色
"""
import os
import sys
import json
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
LOGS = os.path.join(HERE, "fake_logs")

os.environ.setdefault("SLG_LOG_DIR", LOGS)

spec = importlib.util.spec_from_file_location("ssh_login_log_main", os.path.join(SRC, "ssh_login_log_main.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# 开发环境把数据目录挪到 dev/.data，避免污染 src/
DATA = os.path.join(HERE, ".data")
if not os.path.isdir(DATA):
    os.makedirs(DATA)
mod.DATA_PATH = DATA
mod.CONF_FILE = os.path.join(DATA, "config.json")
mod.GEO_FILE = os.path.join(DATA, "ip_area.json")
mod.BLACK_FILE = os.path.join(DATA, "blacklist.json")
mod.WHITE_FILE = os.path.join(DATA, "whitelist.json")

plugin = mod.ssh_login_log_main()

# 本地无防火墙，用内存集合模拟封禁状态
FAKE_BLOCKED = set()


def _fake_ban(args):
    addr = str((args or {}).get("addr") or "").strip()
    if plugin._whitelisted(addr):
        return {"status": False, "msg": "%s 在白名单中，已拒绝禁用" % addr}
    FAKE_BLOCKED.add(addr)
    return {"status": True, "data": {"addr": addr, "via": "mock", "blocked": True}}


def _fake_unban(args):
    addr = str((args or {}).get("addr") or "").strip()
    FAKE_BLOCKED.discard(addr)
    return {"status": True, "data": {"addr": addr, "blocked": False}}


plugin.ban_ip = _fake_ban
plugin.unban_ip = _fake_unban
plugin._blocked_set = lambda: set(FAKE_BLOCKED)

INDEX_PATH = os.path.join(SRC, "index.html")


def read_index():
    with open(INDEX_PATH, encoding="utf-8") as f:
        return f.read()

WRAP = """<!doctype html><html><head><meta charset="utf-8">
<title>SSH 登录审计</title>
<style>body{margin:0;padding:16px;background:%(bg)s;font-family:-apple-system,"Microsoft YaHei",sans-serif}</style>
%(pre)s
</head><body>
%(body)s
</body></html>"""


DIALOG_HTML = """<!doctype html><html><head><meta charset="utf-8">
<style>
body{margin:0;background:#eef1f3;font-family:-apple-system,"Microsoft YaHei",sans-serif}
.layui-layer{position:fixed;top:60px;left:80px;width:700px;height:600px;background:#fff;
  border-radius:8px;box-shadow:0 10px 34px rgba(0,0,0,.18);overflow:hidden}
.layui-layer iframe{display:block;width:100%;height:100%;border:0}
</style></head><body>
<div class="layui-layer" style="width:570px;height:450px">
<iframe src="/" style="width:1200px;height:100%;zoom:0.475;border:0"></iframe></div>
</body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/dialog":
            return self._send(200, DIALOG_HTML, "text/html; charset=utf-8")
        if u.path in ("/", "/index.html"):
            q = parse_qs(u.query)
            dark = q.get("theme", [""])[0] == "dark"
            pre = "<script>localStorage.setItem('slg_theme','%s')</script>" % ("dark" if dark else "auto")
            html = WRAP % {"bg": "#1c1f24" if dark else "#f1f3f4", "pre": pre, "body": read_index()}
            return self._send(200, html, "text/html; charset=utf-8")
        if u.path.startswith("/plugin"):
            q = parse_qs(u.query)
            return self._call(q.get("s", [""])[0], {k: v[0] for k, v in q.items()})
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8") if n else ""
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        if u.path.startswith("/plugin"):
            q = parse_qs(u.query)
            return self._call(q.get("s", [""])[0], form)
        return self._send(404, "not found", "text/plain")

    def _call(self, s, args):
        fn = getattr(plugin, s, None)
        if not s or not callable(fn) or s.startswith("_"):
            return self._send(200, json.dumps({"status": False, "msg": "unknown method %s" % s}))
        try:
            res = fn(args)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._send(200, json.dumps({"status": False, "msg": "%s: %s" % (type(e).__name__, e)}))
        if s == "get_online" and not (res.get("data") or {}).get("rows"):
            res["data"] = {"total": 2, "rows": [
                {"user": "root", "tty": "sshd", "ip": "103.116.245.55", "ts": 0,
                 "time": "2026-11-16 09:33", "duration": 2820, "duration_text": "47 分 0 秒",
                 "pid": 1895858, "remote_port": 42832},
                {"user": "deploy", "tty": "pts/0", "ip": "2402:4e00::8cc0", "ts": 0,
                 "time": "2026-11-16 10:01", "duration": 780, "duration_text": "13 分 0 秒",
                 "pid": 1903027, "remote_port": 36690},
            ]}
        return self._send(200, json.dumps(res, ensure_ascii=False))

    def log_message(self, fmt, *a):
        sys.stderr.write("%s\n" % (fmt % a))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8891
    print("mock panel on http://127.0.0.1:%d/  (logs: %s)" % (port, LOGS))
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
