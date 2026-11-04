"""境外網頁代理（Render 免費方案）。

用法：登入後把網址貼進首頁，或直接開 /p/https/example.com/path 。
所有對外連線由 Render 美國機房發出，瀏覽器看到的就是境外 IP 的結果。

安全：
- PROXY_PASS 未設 → 除 /healthz 外整站 503，避免變成公開代理。
- 目標主機先解析、驗證不是私有 / loopback / link-local 位址，然後**只連驗證過的那個 IP**
  （Host 標頭、TLS SNI 與憑證驗證仍用原主機名），杜絕 DNS 重綁定。
- 每個請求用獨立的 requests.Session，不保存任何上游 cookie，不同瀏覽器之間不會互相汙染。
- 回應剝掉 CSP / HSTS / X-Frame-Options，以免改寫後的頁面被瀏覽器擋掉。

已知限制（架構性，單一網域做不到）：所有被代理的網站都跑在代理這個瀏覽器 origin 底下，
惡意網頁理論上可讀到你透過本代理瀏覽的其他網站內容。只供本人瀏覽公開資訊，
不要透過代理登入銀行、信箱等敏感帳號。
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
from requests.adapters import HTTPAdapter

app = Flask(__name__, static_folder=None)

PROXY_PASS = os.environ.get("PROXY_PASS", "").strip()
_SECRET = (os.environ.get("PROXY_SECRET") or PROXY_PASS or "unset").encode()
AUTH_COOKIE = "__overseas_pxa"
MAX_REWRITE_BYTES = 8 * 1024 * 1024          # 解壓後超過就不改寫、直接串流
UPSTREAM_TIMEOUT = (10, 60)
ALLOWED_PORTS = {80, 443, 8080, 8443}
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

# ─── 認證 ────────────────────────────────────────────────────────────────────

def _token() -> str:
    return hmac.new(_SECRET, b"proxy-ok", hashlib.sha256).hexdigest()


def _authed() -> bool:
    if not PROXY_PASS:
        return False
    tok = _token().encode()
    # 同名上游 cookie 可能排在前面（R11）：任何一個值符合即可
    return any(_TOKEN_RE.match(v) and hmac.compare_digest(v.encode(), tok)
               for v in request.cookies.getlist(AUTH_COOKIE))


@app.before_request
def _gate():
    if request.path == "/healthz":
        return None
    if not PROXY_PASS:
        return Response("PROXY_PASS 未設定，代理停用。", 503, mimetype="text/plain; charset=utf-8")
    if request.path in ("/", "/login"):
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


_SKIP_PREFIX = ("javascript:", "data:", "mailto:", "tel:", "blob:", "about:", "#")


def rewrite_ref(ref: str, base: str) -> str:
    r = ref.strip()
    if not r or r.lower().startswith(_SKIP_PREFIX) or r.startswith("/p/http"):
        return ref
    try:
        return to_proxy(urljoin(base, r))
    except ValueError:
        return ref


def raw_upstream_target(scheme: str, host: str, path: str) -> str:
    """用瀏覽器送來的原始（未解碼）request-target 組上游 URL（R05）。"""
    prefix = f"/p/{scheme}/{host}"
    raw = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI") or ""
    if raw.startswith(prefix + "/") or raw == prefix or raw.startswith(prefix + "?"):
        rest = raw[len(prefix):] or "/"
    else:  # 沒拿到原始字串時退回路由參數重新編碼
        rest = "/" + quote(path, safe="/:@!$&'()*+,;=-._~%")
        if request.query_string:
            rest += "?" + request.query_string.decode("latin-1")
    if not rest.startswith("/"):
        rest = "/" + rest
    return f"{scheme}://{host}{rest}"


# ─── HTML / CSS 改寫 ────────────────────────────────────────────────────────

_ATTR_RE = re.compile(
    r"""(\s(?:href|src|action|poster|formaction|data-src|data-href)\s*=\s*)(?:(["'])(.*?)\2|([^\s"'=<>`]+))""",
    re.I | re.S,
)
_SRCSET_RE = re.compile(r"""(\s(?:srcset|data-srcset)\s*=\s*)(?:(["'])(.*?)\2|([^\s"'=<>`]+))""", re.I | re.S)
_STYLE_ATTR_RE = re.compile(r"""(\sstyle\s*=\s*)(["'])(.*?)\2""", re.I | re.S)
_STYLE_BLOCK_RE = re.compile(r"(<style\b[^>]*>)(.*?)(</style\s*>)", re.I | re.S)
_SCRIPT_RE = re.compile(r"(<script\b[^>]*>)(.*?)(</script\s*>)", re.I | re.S)
_BASE_TAG_RE = re.compile(r"<base\s[^>]*>", re.I | re.S)
_BASE_HREF_RE = re.compile(r"""(\shref\s*=\s*)(?:(["'])(.*?)\2|([^\s"'>]+))""", re.I | re.S)
_CSS_URL_RE = re.compile(r"""url\(\s*(["']?)(?!data:)([^"')]+)\1\s*\)""", re.I)
_CSS_IMPORT_RE = re.compile(r"""@import\s+(["'])([^"']+)\1""", re.I)
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I | re.S)
_REFRESH_URL_RE = re.compile(r"""(content\s*=\s*(["'])[^;"']*;\s*url\s*=\s*)([^"'>]+)""", re.I)
_INTEGRITY_RE = re.compile(r"""\s(?:integrity|crossorigin)\s*=\s*(?:(["']).*?\1|[^\s"'=<>`]+)""", re.I)
_HEAD_RE = re.compile(r"<head[^>]*>", re.I)

SHIM = """<script>(function(){
var B='/p/%(scheme)s/%(host)s',O=location.origin;
function A(a){return (a.origin===O&&a.pathname.indexOf('/p/http')===0)?a.pathname+a.search+a.hash:(a.origin===O?B+a.pathname+a.search+a.hash:'/p/'+a.protocol.slice(0,-1)+'/'+a.host+a.pathname+a.search+a.hash);}
function R(u){try{if(typeof u!=='string')return u;var s=u.trim();if(!s)return u;
if(/^(javascript|data|mailto|tel|blob|about):/i.test(s)||s.indexOf('/p/http')===0||s.charAt(0)==='#')return u;
if(/^https?:\\/\\//i.test(s))return A(new URL(s));
if(s.indexOf('//')===0)return A(new URL('%(scheme)s:'+s));
if(s.charAt(0)==='/')return B+s;return u;}catch(e){return u;}}
var f=window.fetch;window.fetch=function(i,o){if(typeof i==='string')i=R(i);else if(i instanceof Request){var n=R(i.url);if(n!==i.url)i=new Request(n,i);}return f.call(this,i,o);};
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


def _attr_sub(base: str):
    def _attr(m):
        val = m.group(3) if m.group(2) is not None else m.group(4)
        q = m.group(2) or '"'
        return f"{m.group(1)}{q}{rewrite_ref(val, base)}{q}"
    return _attr


def _rewrite_tag_attrs(tag: str, base: str) -> str:
    """只改一個開頭標籤裡的 URL 屬性並拿掉 SRI（用於 <script ...> 開頭標籤，F02）。"""
    tag = _ATTR_RE.sub(_attr_sub(base), tag)
    return _INTEGRITY_RE.sub("", tag)


def _rewrite_markup(text: str, base: str) -> str:
    """只處理非 <script> 的片段（R06）。"""
    def _srcset(m):
        raw = m.group(3) if m.group(2) is not None else m.group(4)
        q = m.group(2) or '"'
        if "data:" in raw.lower():               # data URL 含逗號，拆不準就原樣保留（F05）
            return m.group(0)
        parts = []
        for cand in raw.split(","):
            bits = cand.strip().split(None, 1)
            if not bits:
                continue
            bits[0] = rewrite_ref(bits[0], base)
            parts.append(" ".join(bits))
        return f"{m.group(1)}{q}{', '.join(parts)}{q}"

    def _meta(m):                                # http-equiv=refresh 不限屬性順序（F05）
        tag = m.group(0)
        if not re.search(r"""http-equiv\s*=\s*["']?\s*refresh""", tag, re.I):
            return tag
        return _REFRESH_URL_RE.sub(lambda r: r.group(1) + rewrite_ref(r.group(3), base), tag)

    text = _META_TAG_RE.sub(_meta, text)
    text = _ATTR_RE.sub(_attr_sub(base), text)
    text = _SRCSET_RE.sub(_srcset, text)
    text = _INTEGRITY_RE.sub("", text)          # 改寫過的資源 SRI 一定不符，拿掉
    text = _STYLE_ATTR_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{rewrite_css(m.group(3), base)}{m.group(2)}", text)
    text = _STYLE_BLOCK_RE.sub(lambda m: m.group(1) + rewrite_css(m.group(2), base) + m.group(3), text)
    return text


def rewrite_html(text: str, doc_url: str) -> str:
    pieces = _SCRIPT_RE.split(text)             # [markup, open_tag, body, close_tag, markup, ...]
    # 第一個真正的 <base>（只在非 script 片段找，F04）：對文件 URL 解析一次，標籤本身直接換成代理路徑
    base = doc_url
    for i in range(0, len(pieces), 4):
        mb = _BASE_TAG_RE.search(pieces[i])
        if not mb:
            continue
        tag = mb.group(0)
        mh = _BASE_HREF_RE.search(tag)
        if mh:
            href = (mh.group(3) if mh.group(2) is not None else mh.group(4)).strip()
            try:
                base = urljoin(doc_url, href)
            except ValueError:
                base = doc_url
            new_tag = tag[:mh.start()] + f' href="{to_proxy(base)}"' + tag[mh.end():]
            pieces[i] = pieces[i][:mb.start()] + new_tag + pieces[i][mb.end():]
        break
    for i in range(0, len(pieces), 4):
        pieces[i] = _rewrite_markup(pieces[i], base)
        if i + 1 < len(pieces):
            pieces[i + 1] = _rewrite_tag_attrs(pieces[i + 1], base)   # <script src=...> 要走代理（F02）
    text = "".join(pieces)
    sp = urlsplit(doc_url)
    shim = SHIM % {"scheme": sp.scheme, "host": sp.netloc}
    text, n = _HEAD_RE.subn(lambda m: m.group(0) + shim, text, count=1)
    if n == 0:
        text = shim + text
    return text


_CHARSET_HDR_RE = re.compile(r"charset=[\"']?\s*([\w.:-]+)", re.I)
_META_CHARSET_RE = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([\w.:-]+)""", re.I)
_CSS_CHARSET_RE = re.compile(rb"""^\s*@charset\s+["']([\w.:-]+)["']""", re.I)


def detect_encoding(body: bytes, ctype: str, is_css: bool) -> str:
    """HTTP charset > BOM > <meta charset> / @charset > UTF-8（R08：不吃 requests 的 ISO-8859-1 預設）。"""
    m = _CHARSET_HDR_RE.search(ctype or "")
    if m:
        return m.group(1)
    if body.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if body.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    head = body[:4096]
    m = _CSS_CHARSET_RE.match(head) if is_css else _META_CHARSET_RE.search(head)
    return m.group(1).decode("ascii", "replace") if m else "utf-8"


def decode_body(body: bytes, enc: str) -> str:
    try:
        return body.decode(enc, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


# ─── SSRF 防護 + 連線釘住（R01） ────────────────────────────────────────────

def resolve_public(host: str, scheme: str) -> tuple[str, str, int]:
    """回傳 (hostname, 驗證過的 IP, port)。任何一個解析結果落在內部網段就拒絕。"""
    sp = urlsplit(f"//{host}")
    hostname = (sp.hostname or "").strip(".").lower()
    try:
        port = sp.port
    except ValueError:
        abort(403, "不允許的連接埠")
    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        abort(403, "不允許的連接埠")
    if not hostname or hostname == "localhost" or hostname.endswith((".internal", ".local", ".localhost")):
        abort(403, "不允許的主機")
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        abort(502, f"無法解析主機：{hostname}")
    if not infos:
        abort(502, "無法解析主機")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified or getattr(ip, "ipv4_mapped", None)):
            abort(403, "目標位於內部網段，拒絕")
        ips.append(ip)
    ips.sort(key=lambda a: a.version)           # 先用 IPv4（Render 出口沒有 IPv6）
    return hostname, str(ips[0]), port


class PinnedAdapter(HTTPAdapter):
    """URL 用 IP 連，但 SNI 與憑證主機名驗證仍用原主機名。"""

    def __init__(self, hostname: str):
        self._hostname = hostname
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **kw):
        kw["server_hostname"] = self._hostname
        kw["assert_hostname"] = self._hostname
        super().init_poolmanager(connections, maxsize, block, **kw)


def new_session(hostname: str) -> requests.Session:
    s = requests.Session()
    s.trust_env = False                          # 不吃環境 proxy，連線目標只有我們釘的 IP
    s.mount("https://", PinnedAdapter(hostname))
    s.mount("http://", HTTPAdapter(max_retries=0))   # 明文 HTTP 不帶 TLS 參數（F01）
    return s


def pin_url(target: str, ip: str, port: int) -> str:
    sp = urlsplit(target)
    host_part = f"[{ip}]" if ":" in ip else ip
    default = 443 if sp.scheme == "https" else 80
    netloc = host_part if port == default else f"{host_part}:{port}"
    return sp._replace(netloc=netloc).geturl()


# ─── 標頭處理（R09） ────────────────────────────────────────────────────────

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
    "trailer", "trailers", "transfer-encoding", "upgrade", "content-length",
}
_STRIP_RESP = _HOP_BY_HOP | {
    "content-encoding",                          # requests 已解壓；請求端的 Content-Encoding 原樣轉送（F06）
    "content-security-policy", "content-security-policy-report-only", "x-frame-options",
    "strict-transport-security", "public-key-pins", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy", "report-to", "nel", "alt-svc",
    "set-cookie", "location", "link",
    "cache-control", "expires", "pragma", "vary",   # 代理回應一律 private（F09）
}
_STRIP_REQ = _HOP_BY_HOP | {"host", "cookie", "referer", "origin", "accept-encoding", "x-real-ip", "true-client-ip",
                            "cdn-loop", "forwarded", "via", "x-request-start", "x-request-id"}
_PRIVATE_CACHE = [("Cache-Control", "private, no-cache"), ("Vary", "Cookie")]
_STRIP_REQ_PREFIX = ("x-forwarded-", "x-render-", "render-", "cf-", "x-real-")

_PROXY_PATH_RE = re.compile(r"^/p/(https?)/([^/]+)")


def _nominated(headers) -> set[str]:
    return {h.strip().lower() for h in (headers.get("Connection") or "").split(",") if h.strip()}


def _strip_own_cookies(raw: str) -> str:
    keep = [c.strip() for c in raw.split(";") if c.strip() and not c.strip().startswith(AUTH_COOKIE + "=")]
    return "; ".join(keep)


def _rewrite_set_cookie(value: str, scheme: str, host: str) -> str | None:
    parts = [p.strip() for p in value.split(";")]
    if parts[0].split("=", 1)[0].strip() == AUTH_COOKIE:
        return None                              # 上游不得覆寫我們的認證 cookie 名（R11）
    out = [parts[0]]
    for p in parts[1:]:
        k = p.split("=", 1)[0].lower()
        if k in ("domain", "samesite", "partitioned", "secure"):
            continue
        if k == "path":
            sub = p.split("=", 1)[1] if "=" in p else "/"
            out.append(f"Path=/p/{scheme}/{host}{sub if sub.startswith('/') else '/' + sub}")
            continue
        out.append(p)
    if not any(x.lower().startswith("path=") for x in out):
        out.append(f"Path=/p/{scheme}/{host}/")
    out.append("SameSite=Lax")
    if _is_https():
        out.append("Secure")
    return "; ".join(out)


def _is_https() -> bool:
    return request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"


# ─── 代理本體 ───────────────────────────────────────────────────────────────

def _read_limited(up, limit: int):
    """邊讀邊算解壓後大小（R04）。回傳 (prefix, 剩餘 iterator 或 None)。"""
    buf = bytearray()
    it = up.iter_content(64 * 1024)
    for chunk in it:
        buf += chunk
        if len(buf) > limit:
            return bytes(buf), it
    return bytes(buf), None


@app.route("/p/<scheme>/<host>/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.route("/p/<scheme>/<host>/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy(scheme: str, host: str, path: str):
    if scheme not in ("http", "https"):
        abort(400)
    hostname, ip, port = resolve_public(host, scheme)
    target = raw_upstream_target(scheme, host, path)

    drop = _STRIP_REQ | _nominated(request.headers)
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in drop and not k.lower().startswith(_STRIP_REQ_PREFIX)}
    headers["Host"] = host
    headers["Accept-Encoding"] = "gzip, deflate"
    cookie = _strip_own_cookies(request.headers.get("Cookie", ""))
    if cookie:
        headers["Cookie"] = cookie
    ref = request.headers.get("Referer", "")
    rs = urlsplit(ref) if ref else None
    m = _PROXY_PATH_RE.match(rs.path) if rs else None
    if m:                                        # Referer 連 query 一起還原（F07）
        headers["Referer"] = f"{m.group(1)}://{m.group(2)}" + rs.path[len(m.group(0)):] + (f"?{rs.query}" if rs.query else "")
    origin = request.headers.get("Origin")
    if origin:
        if origin == "null":
            headers["Origin"] = "null"           # opaque origin 原樣保留
        elif m:
            headers["Origin"] = f"{m.group(1)}://{m.group(2)}"
        else:                                    # no-referrer 頁面：最合理的來源就是目標站本身
            headers["Origin"] = f"{scheme}://{host}"

    session = new_session(hostname)
    try:
        up = session.request(
            request.method, pin_url(target, ip, port), headers=headers,
            data=request.get_data() if request.method not in ("GET", "HEAD") else None,
            stream=True, allow_redirects=False, timeout=UPSTREAM_TIMEOUT,
        )
    except requests.RequestException as e:
        session.close()
        return Response(f"上游連線失敗：{type(e).__name__}", 502, mimetype="text/plain; charset=utf-8")

    drop_resp = _STRIP_RESP | _nominated(up.headers)
    resp_headers = [(k, v) for k, v in up.headers.items() if k.lower() not in drop_resp] + _PRIVATE_CACHE
    if "Location" in up.headers:
        resp_headers.append(("Location", rewrite_ref(up.headers["Location"], target)))
    for sc in up.raw.headers.getlist("Set-Cookie"):
        rc = _rewrite_set_cookie(sc, scheme, host)
        if rc:
            resp_headers.append(("Set-Cookie", rc))

    ctype = up.headers.get("Content-Type", "")
    is_html = "text/html" in ctype or "application/xhtml" in ctype
    is_css = "text/css" in ctype
    partial = up.status_code == 206 or "Content-Range" in up.headers
    rewritable = (is_html or is_css) and request.method != "HEAD" and not partial   # 片段不改寫（F08）

    def _close():
        up.close()
        session.close()

    if rewritable:
        try:
            prefix, rest = _read_limited(up, MAX_REWRITE_BYTES)
        except requests.RequestException as e:
            _close()
            return Response(f"上游讀取失敗：{type(e).__name__}", 502, mimetype="text/plain; charset=utf-8")
        if rest is None:
            _close()
            enc = detect_encoding(prefix, ctype, is_css)
            text = decode_body(prefix, enc)
            text = rewrite_html(text, target) if is_html else rewrite_css(text, target)
            resp_headers = [(k, v) for k, v in resp_headers if k.lower() != "content-type"]
            resp_headers.append(("Content-Type", ("text/html" if is_html else "text/css") + "; charset=utf-8"))
            return Response(text.encode("utf-8"), up.status_code, resp_headers)

        def gen_big():                           # 太大：不改寫，前綴＋剩餘直接串流
            try:
                yield prefix
                for chunk in rest:
                    if chunk:
                        yield chunk
            finally:
                _close()
        return Response(stream_with_context(gen_big()), up.status_code, resp_headers)

    def gen():
        try:
            for chunk in up.iter_content(64 * 1024):
                if chunk:
                    yield chunk
        finally:
            _close()

    return Response(stream_with_context(gen()), up.status_code, resp_headers)


@app.route("/<path:anything>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], provide_automatic_options=False)
def catch_all(anything: str):
    """JS 用絕對路徑 (/foo) 打到代理根目錄時，用 Referer 推回原站。"""
    ref = request.headers.get("Referer", "")
    m = _PROXY_PATH_RE.match(urlsplit(ref).path) if ref else None
    if not m:
        abort(404)
    raw = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI") or ""
    if raw.startswith("/"):
        rest = raw
    else:
        rest = "/" + quote(anything, safe="/:@!$&'()*+,;=-._~%")
        if request.query_string:
            rest += "?" + request.query_string.decode("latin-1")
    return redirect(f"/p/{m.group(1)}/{m.group(2)}{rest}", 307)


# ─── 首頁 / 登入 / 健康 ─────────────────────────────────────────────────────

PAGE = """<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>境外代理</title>
<style>body{margin:0;background:#f6f7f9;color:#1b1f24;font:16px/1.6 -apple-system,"PingFang TC",system-ui,sans-serif}
main{max-width:640px;margin:0 auto;padding:48px 16px}h1{font-size:24px;margin:0 0 6px}p.m{color:#5b6470;margin:0 0 24px}
form{display:flex;gap:8px;margin-bottom:16px}input{flex:1;padding:12px 14px;border:1px solid #d5dae0;border-radius:10px;font-size:16px}
button{padding:12px 18px;border:0;border-radius:10px;background:#2457c5;color:#fff;font-size:16px}
.card{background:#fff;border:1px solid #e3e6ea;border-radius:12px;padding:16px 20px;margin-top:20px}code{font:14px ui-monospace,Menlo,monospace}
.err{color:#b42318}.warn{color:#8a5a00}a{color:#2457c5}</style></head><body><main>
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
<div class="card warn"><b>只看公開資訊。</b>所有被代理的網站共用同一個瀏覽器 origin，不要透過代理登入銀行、信箱等敏感帳號。</div>
{% endif %}
</main></body></html>"""


def _egress() -> str:
    try:
        j = requests.get("https://ipinfo.io/json", timeout=6).json()   # 無 session、無 cookie 持久化（R02）
        return f"{j.get('ip','?')} · {j.get('city','')} {j.get('region','')} {j.get('country','')} · {j.get('org','')}"
    except Exception as e:  # noqa: BLE001
        return f"查詢失敗（{type(e).__name__}）"


@app.route("/")
def index():
    authed = _authed()
    html = render_template_string(
        PAGE, authed=authed, next=request.args.get("next", "")[:2000], err=request.args.get("err", ""),
        egress=_egress() if authed else "", base=request.url_root.rstrip("/"),
    )
    return Response(html, 200, _PRIVATE_CACHE, mimetype="text/html")


@app.route("/login", methods=["POST"])
def login():
    nxt = request.form.get("next", "")
    if not nxt.startswith("/p/"):
        nxt = "/"
    given = request.form.get("pass", "").encode("utf-8")
    if hmac.compare_digest(given, PROXY_PASS.encode("utf-8")):       # bytes 比對（R10）
        r = make_response(redirect(nxt))
        r.set_cookie(AUTH_COOKIE, _token(), max_age=30 * 86400, httponly=True, samesite="Lax", secure=_is_https())
        return r
    return redirect("/?err=" + quote("通行碼錯誤") + "&next=" + quote(nxt))


@app.route("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5055)), debug=False)
