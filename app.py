"""境外網頁代理（Render 免費方案）。

用法：登入後把網址貼進首頁，或直接開 /p/https/example.com/path 。
所有對外連線由 Render 美國機房發出，瀏覽器看到的就是境外 IP 的結果。

安全：
- PROXY_PASS 未設 → 整站 503，避免變成公開代理。
- 目標主機解析到私有 / loopback / link-local 位址一律拒絕（SSRF）。
- 回應剝掉 CSP / HSTS / X-Frame-Options，以免改寫後的頁面被瀏覽器擋掉。
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import socket
from urllib.parse import quote, urljoin, urlsplit

import requests
from flask import Flask, Response, abort, make_response, redirect, render_template_string, request, stream_with_context

app = Flask(__name__, static_folder=None)

PROXY_PASS = os.environ.get("PROXY_PASS", "").strip()
_SECRET = (os.environ.get("PROXY_SECRET") or PROXY_PASS or "unset").encode()
AUTH_COOKIE = "pxa"
MAX_REWRITE_BYTES = 8 * 1024 * 1024          # 超過就不改寫、直接串流
UPSTREAM_TIMEOUT = (10, 60)
ALLOWED_PORTS = {80, 443, 8080, 8443}

SESSION = requests.Session()

# ─── 認證 ────────────────────────────────────────────────────────────────────

def _token() -> str:
    return hmac.new(_SECRET, b"proxy-ok", hashlib.sha256).hexdigest()


def _authed() -> bool:
    return bool(PROXY_PASS) and hmac.compare_digest(request.cookies.get(AUTH_COOKIE, ""), _token())


@app.before_request
def _gate():
    if request.path in ("/healthz",):
        return None
    if not PROXY_PASS:
        return Response("PROXY_PASS 未設定，代理停用。", 503, mimetype="text/plain; charset=utf-8")
    if request.path == "/" or request.path == "/login":
        return None
    if not _authed():
        if request.path.startswith("/p/"):
            return redirect("/?next=" + quote(request.full_path.rstrip("?")))
        abort(401)
    return None


# ─── URL 轉換 ───────────────────────────────────────────────────────────────

def to_proxy(abs_url: str) -> str:
    """https://host:port/path?q → /p/https/host:port/path?q"""
    sp = urlsplit(abs_url)
    if sp.scheme not in ("http", "https") or not sp.netloc:
        return abs_url
    path = sp.path or "/"
    out = f"/p/{sp.scheme}/{sp.netloc}{path}"
    if sp.query:
        out += "?" + sp.query
    if sp.fragment:
        out += "#" + sp.fragment
    return out


def from_proxy(scheme: str, host: str, path: str) -> str:
    url = f"{scheme}://{host}/{path}"
    if request.query_string:
        url += "?" + request.query_string.decode("latin-1")
    return url


_SKIP_PREFIX = ("javascript:", "data:", "mailto:", "tel:", "blob:", "about:", "#")


def rewrite_ref(ref: str, base: str) -> str:
    r = ref.strip()
    if not r or r.lower().startswith(_SKIP_PREFIX) or r.startswith("/p/http"):
        return ref
    try:
        return to_proxy(urljoin(base, r))
    except ValueError:
        return ref


_ATTR_RE = re.compile(
    r"""(\s(?:href|src|action|poster|formaction|data-src|data-href)\s*=\s*)(["'])(.*?)\2""",
    re.I | re.S,
)
_SRCSET_RE = re.compile(r"""(\s(?:srcset|data-srcset)\s*=\s*)(["'])(.*?)\2""", re.I | re.S)
_CSS_URL_RE = re.compile(r"""url\(\s*(["']?)(?!data:)([^"')]+)\1\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+(["'])([^"']+)\1""", re.I)
_META_REFRESH_RE = re.compile(r"""(<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^;"']*;\s*url=)([^"'>]+)""", re.I)
_INTEGRITY_RE = re.compile(r"""\s(?:integrity|crossorigin)\s*=\s*(["']).*?\1""", re.I)
_HEAD_RE = re.compile(r"<head[^>]*>", re.I)

SHIM = """<script>(function(){
var B='/p/%(scheme)s/%(host)s';
function R(u){try{if(typeof u!=='string')return u;var s=u.trim();if(!s)return u;
if(/^(javascript|data|mailto|tel|blob|about):/i.test(s)||s.indexOf('/p/http')===0||s.charAt(0)==='#')return u;
if(/^https?:\\/\\//i.test(s)){var a=new URL(s);return '/p/'+a.protocol.slice(0,-1)+'/'+a.host+a.pathname+a.search+a.hash;}
if(s.indexOf('//')===0){var b=new URL('%(scheme)s:'+s);return '/p/'+b.protocol.slice(0,-1)+'/'+b.host+b.pathname+b.search+b.hash;}
if(s.charAt(0)==='/')return B+s;return u;}catch(e){return u;}}
var f=window.fetch;window.fetch=function(i,o){if(typeof i==='string')i=R(i);else if(i&&i.url){i=new Request(R(i.url),i);}return f.call(this,i,o);};
var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=R(u);return xo.apply(this,arguments);};
if(navigator.sendBeacon){var sb=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){return sb(R(u),d);};}
var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^(src|href|action|poster|formaction)$/i.test(n))v=R(v);return sa.call(this,n,v);};
[[HTMLImageElement,'src'],[HTMLScriptElement,'src'],[HTMLIFrameElement,'src'],[HTMLSourceElement,'src'],[HTMLVideoElement,'src'],[HTMLAudioElement,'src'],[HTMLLinkElement,'href'],[HTMLAnchorElement,'href'],[HTMLFormElement,'action']].forEach(function(p){
var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);if(!d||!d.set)return;
Object.defineProperty(p[0].prototype,p[1],{get:d.get,set:function(v){d.set.call(this,R(v));},configurable:true});});
var ps=history.pushState,rs=history.replaceState;history.pushState=function(s,t,u){return ps.call(this,s,t,u==null?u:R(String(u)));};history.replaceState=function(s,t,u){return rs.call(this,s,t,u==null?u:R(String(u)));};
window.open=(function(o){return function(u){arguments[0]=R(u);return o.apply(window,arguments);};})(window.open);
})();</script>"""


def rewrite_css(text: str, base: str) -> str:
    text = _CSS_URL_RE.sub(lambda m: f"url({m.group(1)}{rewrite_ref(m.group(2), base)}{m.group(1)})", text)
    return _CSS_IMPORT_RE.sub(lambda m: f"@import {m.group(1)}{rewrite_ref(m.group(2), base)}{m.group(1)}", text)


def rewrite_html(text: str, base: str) -> str:
    sp = urlsplit(base)
    text = _ATTR_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{rewrite_ref(m.group(3), base)}{m.group(2)}", text)

    def _srcset(m):
        parts = []
        for cand in m.group(3).split(","):
            bits = cand.strip().split(None, 1)
            if not bits:
                continue
            bits[0] = rewrite_ref(bits[0], base)
            parts.append(" ".join(bits))
        return f"{m.group(1)}{m.group(2)}{', '.join(parts)}{m.group(2)}"

    text = _SRCSET_RE.sub(_srcset, text)
    text = _META_REFRESH_RE.sub(lambda m: m.group(1) + rewrite_ref(m.group(2), base), text)
    text = _INTEGRITY_RE.sub("", text)          # 改寫過的資源 SRI 一定不符，拿掉
    text = rewrite_css(text, base)
    shim = SHIM % {"scheme": sp.scheme, "host": sp.netloc}
    text, n = _HEAD_RE.subn(lambda m: m.group(0) + shim, text, count=1)
    if n == 0:
        text = shim + text
    return text


# ─── SSRF 防護 ──────────────────────────────────────────────────────────────

def assert_public_host(host: str) -> None:
    hostname, _, port = host.rpartition(":") if host.count(":") == 1 and not host.startswith("[") else (host, "", "")
    hostname = hostname or host
    hostname = hostname.strip("[]")
    if port and (not port.isdigit() or int(port) not in ALLOWED_PORTS):
        abort(403, "不允許的連接埠")
    if hostname.lower() in ("localhost",) or hostname.endswith(".internal") or hostname.endswith(".local"):
        abort(403, "不允許的主機")
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        abort(502, f"無法解析主機：{hostname}")
    if not infos:
        abort(502, "無法解析主機")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            abort(403, "目標位於內部網段，拒絕")


# ─── 代理本體 ───────────────────────────────────────────────────────────────

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-encoding", "content-length",
}
_STRIP_RESP = _HOP_BY_HOP | {
    "content-security-policy", "content-security-policy-report-only", "x-frame-options",
    "strict-transport-security", "public-key-pins", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy", "report-to", "nel", "alt-svc",
    "set-cookie", "location", "link",
}
_STRIP_REQ = {"host", "cookie", "referer", "origin", "accept-encoding", "content-length", "connection",
              "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "cf-connecting-ip",
              "true-client-ip", "x-request-start", "render-proxy-ttl", "cdn-loop", "forwarded", "via"}

_PROXY_PATH_RE = re.compile(r"^/p/(https?)/([^/]+)")


def _strip_own_cookies(raw: str) -> str:
    keep = [c for c in raw.split(";") if c.strip() and not c.strip().startswith(AUTH_COOKIE + "=")]
    return "; ".join(c.strip() for c in keep)


def _rewrite_set_cookie(value: str, scheme: str, host: str) -> str:
    parts = [p.strip() for p in value.split(";")]
    out = [parts[0]]
    for p in parts[1:]:
        k = p.split("=", 1)[0].lower()
        if k in ("domain", "samesite", "partitioned"):
            continue
        if k == "path":
            sub = p.split("=", 1)[1] if "=" in p else "/"
            out.append(f"Path=/p/{scheme}/{host}{sub if sub.startswith('/') else '/' + sub}")
            continue
        if k == "secure":
            continue
        out.append(p)
    if not any(x.lower().startswith("path=") for x in out):
        out.append(f"Path=/p/{scheme}/{host}/")
    out.append("SameSite=Lax")
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        out.append("Secure")
    return "; ".join(out)


@app.route("/p/<scheme>/<host>/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.route("/p/<scheme>/<host>/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy(scheme: str, host: str, path: str):
    if scheme not in ("http", "https"):
        abort(400)
    assert_public_host(host)
    target = from_proxy(scheme, host, path)

    headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_REQ}
    headers["Host"] = host
    headers["Accept-Encoding"] = "gzip, deflate"
    cookie = _strip_own_cookies(request.headers.get("Cookie", ""))
    if cookie:
        headers["Cookie"] = cookie
    ref = request.headers.get("Referer", "")
    m = _PROXY_PATH_RE.match(urlsplit(ref).path) if ref else None
    if m:
        headers["Referer"] = f"{m.group(1)}://{m.group(2)}" + urlsplit(ref).path[len(m.group(0)):]
        if request.headers.get("Origin"):
            headers["Origin"] = f"{m.group(1)}://{m.group(2)}"

    try:
        up = SESSION.request(
            request.method, target, headers=headers,
            data=request.get_data() if request.method not in ("GET", "HEAD") else None,
            stream=True, allow_redirects=False, timeout=UPSTREAM_TIMEOUT,
        )
    except requests.RequestException as e:
        return Response(f"上游連線失敗：{type(e).__name__}", 502, mimetype="text/plain; charset=utf-8")

    final_url = up.url or target
    resp_headers = [(k, v) for k, v in up.headers.items() if k.lower() not in _STRIP_RESP]
    if "Location" in up.headers:
        resp_headers.append(("Location", rewrite_ref(up.headers["Location"], final_url)))
    for sc in up.raw.headers.getlist("Set-Cookie"):
        resp_headers.append(("Set-Cookie", _rewrite_set_cookie(sc, scheme, host)))

    ctype = up.headers.get("Content-Type", "")
    clen = int(up.headers.get("Content-Length") or 0)
    is_html = "text/html" in ctype or "application/xhtml" in ctype
    is_css = "text/css" in ctype
    rewritable = (is_html or is_css) and clen <= MAX_REWRITE_BYTES and request.method != "HEAD"

    if rewritable:
        body = up.content
        if len(body) > MAX_REWRITE_BYTES:
            return Response(body, up.status_code, resp_headers)
        enc = up.encoding or ("utf-8" if is_css else None)
        if enc is None:
            enc = up.apparent_encoding or "utf-8"
        try:
            text = body.decode(enc, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        text = rewrite_html(text, final_url) if is_html else rewrite_css(text, final_url)
        out = text.encode("utf-8")
        resp_headers = [(k, v) for k, v in resp_headers if k.lower() != "content-type"]
        resp_headers.append(("Content-Type", ("text/html" if is_html else "text/css") + "; charset=utf-8"))
        return Response(out, up.status_code, resp_headers)

    def gen():
        try:
            for chunk in up.iter_content(64 * 1024):
                if chunk:
                    yield chunk
        finally:
            up.close()

    return Response(stream_with_context(gen()), up.status_code, resp_headers)


@app.route("/<path:anything>", methods=["GET", "POST", "HEAD"])
def catch_all(anything: str):
    """JS 用絕對路徑 (/foo) 打到代理根目錄時，用 Referer 推回原站。"""
    ref = request.headers.get("Referer", "")
    m = _PROXY_PATH_RE.match(urlsplit(ref).path) if ref else None
    if not m:
        abort(404)
    qs = ("?" + request.query_string.decode("latin-1")) if request.query_string else ""
    return redirect(f"/p/{m.group(1)}/{m.group(2)}/{anything}{qs}", 307)


# ─── 首頁 / 登入 / 健康 ─────────────────────────────────────────────────────

PAGE = """<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>境外代理</title>
<style>body{margin:0;background:#f6f7f9;color:#1b1f24;font:16px/1.6 -apple-system,"PingFang TC",system-ui,sans-serif}
main{max-width:640px;margin:0 auto;padding:48px 16px}h1{font-size:24px;margin:0 0 6px}p.m{color:#5b6470;margin:0 0 24px}
form{display:flex;gap:8px;margin-bottom:16px}input{flex:1;padding:12px 14px;border:1px solid #d5dae0;border-radius:10px;font-size:16px}
button{padding:12px 18px;border:0;border-radius:10px;background:#2457c5;color:#fff;font-size:16px}
.card{background:#fff;border:1px solid #e3e6ea;border-radius:12px;padding:16px 20px;margin-top:20px}code{font:14px ui-monospace,Menlo,monospace}
.err{color:#b42318}a{color:#2457c5}</style></head><body><main>
<h1>境外代理</h1>
{% if not authed %}
<p class="m">輸入通行碼。</p>
<form method="post" action="/login"><input type="hidden" name="next" value="{{ next }}"><input name="pass" type="password" placeholder="通行碼" autofocus required><button>登入</button></form>
{% if err %}<p class="err">{{ err }}</p>{% endif %}
{% else %}
<p class="m">貼上要看的網址，連線會從這台境外主機發出。</p>
<form onsubmit="var u=this.u.value.trim();if(!/^https?:\\/\\//i.test(u))u='https://'+u;var a=new URL(u);location.href='/p/'+a.protocol.slice(0,-1)+'/'+a.host+a.pathname+a.search+a.hash;return false;">
<input name="u" placeholder="https://example.com" autofocus required><button>前往</button></form>
<div class="card"><b>這台主機的出口</b><br>{{ egress }}</div>
<div class="card">書籤格式：<code>{{ base }}/p/https/網域/路徑</code><br>登入／影片／重度 JS 的網站可能無法正常運作。</div>
{% endif %}
</main></body></html>"""


def _egress() -> str:
    try:
        j = SESSION.get("https://ipinfo.io/json", timeout=6).json()
        return f"{j.get('ip','?')} · {j.get('city','')} {j.get('region','')} {j.get('country','')} · {j.get('org','')}"
    except Exception as e:  # noqa: BLE001
        return f"查詢失敗（{type(e).__name__}）"


@app.route("/")
def index():
    authed = _authed()
    return render_template_string(
        PAGE, authed=authed, next=request.args.get("next", "")[:2000], err=request.args.get("err", ""),
        egress=_egress() if authed else "", base=request.url_root.rstrip("/"),
    )


@app.route("/login", methods=["POST"])
def login():
    nxt = request.form.get("next", "")
    if not nxt.startswith("/p/"):
        nxt = "/"
    if hmac.compare_digest(request.form.get("pass", ""), PROXY_PASS):
        r = make_response(redirect(nxt))
        r.set_cookie(AUTH_COOKIE, _token(), max_age=30 * 86400, httponly=True, samesite="Lax",
                     secure=request.is_secure or request.headers.get("X-Forwarded-Proto") == "https")
        return r
    return redirect("/?err=" + quote("通行碼錯誤") + "&next=" + quote(nxt))


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5055)), debug=False)
