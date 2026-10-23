#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import hmac
import html
import hashlib
import secrets
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote
from http.cookies import SimpleCookie

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8098"))

SHARE_TOKEN = os.environ.get("SHARE_TOKEN", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

DATA_FILE = Path("/data/shares.json")
STRM_ROOT = Path("/strm").resolve()

MAX_BODY = 1024 * 1024
MAX_BATCH = 100
COOKIE_HOURS = 12

LOCK = threading.RLock()


def now_ts():
    return int(time.time())


def utc_iso(ts):
    if not ts:
        return ""
    return datetime.fromtimestamp(
        int(ts), timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")


def esc(value):
    return html.escape(str(value or ""), quote=True)


def load_shares():
    with LOCK:
        try:
            if not DATA_FILE.exists():
                return {}
            data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            logging.exception("读取分享记录失败")
            return {}


def save_shares(data):
    with LOCK:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = DATA_FILE.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        os.replace(str(tmp), str(DATA_FILE))


def resolve_strm(rel_path):
    rel_path = str(rel_path or "").replace("\\", "/").strip()
    if not rel_path or "\x00" in rel_path:
        raise ValueError("文件路径为空或无效")

    rel = Path(rel_path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("不允许访问目录之外的文件")

    full = (STRM_ROOT / rel).resolve()
    if not full.is_relative_to(STRM_ROOT):
        raise ValueError("文件路径超出媒体目录")

    if full.suffix.lower() != ".strm":
        raise ValueError("只能分享 .strm 文件")

    if not full.is_file():
        raise FileNotFoundError("找不到该 .strm 文件")

    return full


def read_strm(rel_path):
    full = resolve_strm(rel_path)
    content = full.read_text(encoding="utf-8-sig", errors="replace")

    for line in content.splitlines():
        line = line.strip()
        if line:
            parsed = urlparse(line)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError("STRM 文件中的地址不是有效的 HTTP/HTTPS 地址")
            return line

    raise ValueError("STRM 文件内容为空")


def get_play_url(url, user_agent="Mozilla/5.0"):
    response = requests.get(
        url,
        headers={"User-Agent": user_agent},
        allow_redirects=False,
        timeout=20,
        stream=True
    )
    try:
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                raise RuntimeError("SmartStrm 返回了重定向，但没有目标地址")
            return requests.compat.urljoin(url, location)

        raise RuntimeError(
            "SmartStrm 未返回重定向，HTTP " + str(response.status_code)
        )
    finally:
        response.close()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        240000
    ).hex()
    return salt + "$" + digest


def verify_password(password, stored):
    try:
        salt, expected = str(stored).split("$", 1)
        actual = hash_password(password, salt).split("$", 1)[1]
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def share_expired(record):
    expires_at = record.get("expires_at")
    try:
        return bool(expires_at) and now_ts() >= int(expires_at)
    except (TypeError, ValueError):
        return False


def share_password_enabled(record):
    return bool(record.get("password_hash"))


def cookie_secret():
    return hashlib.sha256(
        (ADMIN_TOKEN + "|" + SHARE_TOKEN + "|movie-share-cookie-v2").encode("utf-8")
    ).digest()


def make_cookie_value(token, expires):
    message = token + "|" + str(expires)
    signature = hmac.new(
        cookie_secret(), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return str(expires) + "." + signature


def verify_cookie_value(token, value, record):
    try:
        expires_text, signature = value.split(".", 1)
        expires = int(expires_text)
        if now_ts() >= expires:
            return False

        share_exp = record.get("expires_at")
        if share_exp and expires > int(share_exp):
            return False

        expected = make_cookie_value(token, expires).split(".", 1)[1]
        return hmac.compare_digest(signature, expected)
    except Exception:
        return False


def cookie_name(token):
    return "ms_auth_" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def token_from_path(path):
    match = re.fullmatch(r"/s/([A-Za-z0-9_-]{12,100})(?:/.*)?", path)
    return match.group(1) if match else None


def find_share(token):
    data = load_shares()
    record = data.get(token)
    return data, record


def public_base_url(handler):
    configured = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured

    proto = handler.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
    scheme = "https" if proto == "https" else "http"
    host = handler.headers.get("Host", "zwnas.notedream.com:8098").strip()

    # 避免 Host 头注入路径或 HTML 内容
    if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", host):
        host = "zwnas.notedream.com:8098"

    return scheme + "://" + host


def page_template(title, body):
    return """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;padding:24px;background:#f4f6f9;color:#222;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{max-width:900px;margin:0 auto;background:#fff;padding:24px;border-radius:14px;box-shadow:0 3px 18px #0000000d}}
h1{{font-size:23px;overflow-wrap:anywhere}}
small,.muted{{color:#666}}
button,.button{{display:inline-block;border:0;border-radius:8px;background:#1769d2;color:white;padding:11px 16px;cursor:pointer;text-decoration:none;font-size:15px}}
input,select{{max-width:100%;padding:10px;border:1px solid #ccc;border-radius:7px;font-size:15px}}
input[type=checkbox]{{width:18px;height:18px}}
.row{{margin:14px 0}}
.error{{color:#b42318}}
.success{{color:#067647}}
.item{{padding:14px 0;border-bottom:1px solid #e8e8e8;overflow-wrap:anywhere}}
.actions{{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}}
.secondary{{background:#5c6675}}
.danger{{background:#b42318}}
@media(max-width:600px){{body{{padding:10px}}main{{padding:16px}}}}
</style>
</head>
<body><main>{}</main></body></html>""".format(esc(title), body)


def render_password_page(token, title, message=""):
    msg = '<p class="error">' + esc(message) + '</p>' if message else ""
    body = """
<h1>{title}</h1>
<p>此分享设置了访问密码，请输入密码后继续。</p>
{message}
<form method="post" action="/s/{token}/unlock">
<div class="row"><input type="password" name="password" placeholder="分享密码" required autocomplete="current-password" style="width:100%"></div>
<button type="submit">验证并播放</button>
</form>
<p class="muted">请勿将密码分享给无关人员。</p>
""".format(title=esc(title), token=quote(token), message=msg)
    return page_template("分享验证", body)


def is_unlocked(handler, token, record):
    if not share_password_enabled(record):
        return True

    raw_cookie = handler.headers.get("Cookie", "")
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
        morsel = cookie.get(cookie_name(token))
        if not morsel:
            return False
        return verify_cookie_value(token, morsel.value, record)
    except Exception:
        return False


def get_share_title(record):
    return str(record.get("title") or record.get("path") or "视频分享")


def get_share_path(record):
    return str(record.get("path") or "")


def get_share_url(record):
    # 老版本记录兼容：旧记录可能直接保存了 url
    return str(record.get("url") or "")


def list_strm_files():
    results = []
    if not STRM_ROOT.exists():
        return results

    for path in STRM_ROOT.rglob("*.strm"):
        try:
            if path.is_file():
                rel = path.relative_to(STRM_ROOT).as_posix()
                results.append(rel)
        except (OSError, ValueError):
            continue

    return sorted(results, key=str.casefold)


def admin_page(handler, notice=""):
    files = list_strm_files()
    shares = load_shares()
    base_url = public_base_url(handler)
    now = now_ts()

    file_items = []
    for rel in files:
        file_items.append(
            '<label class="file-row file-item" data-search="' +
            esc(rel.casefold()) + '">' +
            '<input type="checkbox" class="file-check" value="' +
            esc(rel) + '">' +
            '<span class="file-name">' + esc(rel) + '</span>' +
            '<span class="file-type">STRM</span></label>'
        )

    share_items = []
    active_count = 0
    soon_count = 0

    ordered_shares = sorted(
        shares.items(),
        key=lambda pair: (
            pair[1].get("created_at", 0)
            if isinstance(pair[1], dict) else 0
        ),
        reverse=True
    )

    for token, record in ordered_shares:
        if not isinstance(record, dict):
            continue

        title = get_share_title(record)
        rel_path = get_share_path(record)
        url = base_url + "/s/" + quote(str(token))
        expired = share_expired(record)
        expires_at = record.get("expires_at")

        if expired:
            status_html = '<span class="status status-expired">已过期</span>'
        else:
            active_count += 1
            status_html = '<span class="status status-active">有效</span>'
            if expires_at:
                try:
                    if 0 < int(expires_at) - now <= 7 * 86400:
                        soon_count += 1
                    status_html += (
                        '<span class="expiry-text">到期：' +
                        esc(utc_iso(expires_at)) + '</span>'
                    )
                except (TypeError, ValueError):
                    pass
            else:
                status_html += '<span class="expiry-text">永久有效</span>'

        if share_password_enabled(record):
            password_html = '<span class="tag tag-password">已设密码</span>'
        else:
            password_html = '<span class="tag">无需密码</span>'

        share_items.append(
            '<div class="share-row" data-search="' +
            esc((str(title) + " " + str(rel_path) + " " + str(token)).casefold()) +
            '">' +
            '<div class="share-media">' +
            '<div class="media-icon">▶</div>' +
            '<div class="media-info"><strong>' + esc(title) +
            '</strong><span>' + esc(rel_path) + '</span></div></div>' +
            '<div class="share-status">' + status_html + '</div>' +
            '<div class="share-access">' + password_html + '</div>' +
            '<div class="share-link"><input readonly value="' + esc(url) +
            '" aria-label="分享链接" onclick="this.select()"></div>' +
            '<div class="share-actions">' +
            '<button type="button" class="btn btn-small btn-copy" data-token="' +
            esc(token) + '" onclick="copyLink(this)">复制链接</button>' +
            '<a class="btn btn-small btn-quiet" href="' + esc(url) +
            '" target="_blank" rel="noopener">打开</a>' +
            '<button type="button" class="btn btn-small btn-danger" data-token="' +
            esc(token) + '" onclick="revokeShare(this)">撤销</button>' +
            '</div></div>'
        )

    file_html = "\n".join(file_items) if file_items else (
        '<div class="empty-state"><div class="empty-icon">▤</div>'
        '<strong>媒体库暂时为空</strong>'
        '<p>请确认 STRM 目录挂载正常。</p></div>'
    )
    share_html = "\n".join(share_items) if share_items else (
        '<div class="empty-state"><div class="empty-icon">↗</div>'
        '<strong>还没有分享记录</strong>'
        '<p>从媒体库选择视频，即可创建第一条分享。</p></div>'
    )
    notice_html = (
        '<div class="notice">' + esc(notice) + '</div>' if notice else ""
    )

    html = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Movie Share · 分享管理</title>
<style>
:root {
  --bg:#0D1220; --panel:#151B2C; --panel2:#1A2236;
  --border:#293249; --primary:#7667F8; --primary2:#958AFF;
  --text:#F0F2FA; --muted:#929BB2; --green:#43D6A0;
  --amber:#F2BB62; --red:#F07889;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}
button,a{ -webkit-tap-highlight-color:transparent }
button{cursor:pointer}
a{color:inherit;text-decoration:none}
.app{min-height:100vh}
.sidebar{position:fixed;inset:0 auto 0 0;width:242px;padding:27px 17px;
  background:#111727;border-right:1px solid var(--border);
  display:flex;flex-direction:column;z-index:5}
.brand{display:flex;align-items:center;gap:12px;padding:0 8px 30px}
.brand-mark{width:39px;height:39px;border-radius:13px;
  display:grid;place-items:center;background:linear-gradient(140deg,#9486FF,#6554E8);
  box-shadow:0 6px 24px #7667f844;font-size:20px;font-weight:800}
.brand-name{font-size:16px;font-weight:750;letter-spacing:.3px}
.brand-sub{font-size:9px;letter-spacing:1.5px;color:var(--muted);margin-top:2px}
.nav-label{font-size:10px;letter-spacing:1.6px;color:#69748D;
  padding:12px 11px 8px}
.nav-link{display:flex;align-items:center;gap:12px;padding:11px 13px;
  margin:3px 0;border-radius:10px;color:#9BA5BC;transition:.18s}
.nav-link .nav-icon{width:20px;text-align:center;font-size:17px}
.nav-link:hover{background:#1B2337;color:var(--text)}
.nav-link.active{background:#7667f823;color:#B9B0FF;
  box-shadow:inset 3px 0 var(--primary)}
.sidebar-bottom{margin-top:auto}
.service-card{border:1px solid var(--border);border-radius:13px;
  padding:14px;background:#151D2E}
.service-title{font-weight:650;font-size:12px}
.service-sub{font-size:11px;color:var(--muted);margin-top:4px}
.service-dot{display:inline-block;width:7px;height:7px;border-radius:50%;
  background:var(--green);margin-right:7px}
.main{margin-left:242px;min-height:100vh;padding:28px 35px 32px}
.topbar{display:flex;justify-content:space-between;align-items:center;
  gap:15px;padding-bottom:23px;border-bottom:1px solid var(--border)}
.breadcrumb{font-size:12px;color:var(--muted)}
.breadcrumb span{color:#C4BDFF}
.top-right{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:12px}
.avatar{width:33px;height:33px;border-radius:11px;display:grid;place-items:center;
  background:#272449;color:#C5BDFF;font-weight:700}
.hero{display:flex;justify-content:space-between;align-items:flex-end;
  gap:20px;padding:31px 0 25px}
.eyebrow{font-size:10px;font-weight:750;letter-spacing:2px;color:var(--primary2)}
h1{font-size:27px;letter-spacing:-.7px;margin:5px 0 5px;line-height:1.3}
.subtitle{color:var(--muted);font-size:13px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;
  border:1px solid transparent;border-radius:9px;padding:10px 14px;
  background:var(--primary);color:white;font-weight:650;transition:.18s}
.btn:hover{background:#887BFF;transform:translateY(-1px)}
.btn:disabled{opacity:.5;cursor:wait;transform:none}
.btn-quiet{background:#20283B;border-color:#303A52;color:#D5D9E7}
.btn-quiet:hover{background:#2B354D}
.btn-danger{background:#38212F;color:#FF9DAB;border-color:#58303D}
.btn-danger:hover{background:#512636}
.btn-small{padding:7px 10px;font-size:11px;border-radius:7px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px}
.stat{background:var(--panel);border:1px solid var(--border);
  border-radius:14px;padding:19px;min-width:0}
.stat-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
.stat-label{font-size:12px;color:var(--muted)}
.stat-icon{width:34px;height:34px;display:grid;place-items:center;
  background:#7667f821;color:#B9B0FF;border-radius:10px;font-size:17px}
.stat-value{font-size:28px;font-weight:750;letter-spacing:-.8px;margin-top:10px}
.stat-foot{font-size:11px;color:var(--muted);margin-top:3px}
.section{margin-top:28px}
.section-head{display:flex;justify-content:space-between;align-items:center;
  gap:15px;margin-bottom:13px}
.section-title{font-size:16px;font-weight:700}
.section-desc{font-size:11px;color:var(--muted);margin-top:3px}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:9px}
.control{min-width:0;border:1px solid #303A52;border-radius:9px;
  padding:10px 12px;background:#111827;color:var(--text);outline:none}
.control:focus{border-color:var(--primary);box-shadow:0 0 0 3px #7667f822}
.search{width:260px;max-width:100%}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden}
.panel-head{padding:15px 18px;border-bottom:1px solid var(--border);
  display:flex;justify-content:space-between;align-items:center;gap:12px}
.panel-caption{font-size:12px;color:var(--muted)}
.panel-body{padding:0 18px}
.file-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:9px;padding:14px 0}
.file-toolbar .control{flex:1;min-width:160px}
.file-list{max-height:310px;overflow:auto;border-top:1px solid var(--border)}
.file-row{display:flex;align-items:center;gap:12px;padding:12px 8px;
  border-bottom:1px solid #252E42;cursor:pointer;min-width:0}
.file-row:hover{background:#1A2235}
.file-row input{width:16px;height:16px;accent-color:var(--primary);flex:none}
.file-name{overflow-wrap:anywhere;min-width:0;flex:1;font-size:12px}
.file-type{font-size:9px;letter-spacing:.6px;color:#B9B0FF;
  border:1px solid #7667f844;background:#7667f815;padding:3px 6px;border-radius:5px}
.selected-count{font-size:11px;color:var(--muted)}
.create-strip{display:flex;align-items:center;justify-content:space-between;
  gap:15px;padding:15px 18px;background:#191F32}
.create-strip p{margin:0;font-size:11px;color:var(--muted)}
.share-row{display:grid;grid-template-columns:minmax(180px,1.5fr) minmax(100px,.8fr)
  minmax(85px,.6fr) minmax(150px,1.2fr) auto;align-items:center;gap:13px;
  padding:15px 0;border-bottom:1px solid #252E42}
.share-row:last-child{border-bottom:0}
.share-media{display:flex;align-items:center;gap:11px;min-width:0}
.media-icon{width:37px;height:37px;border-radius:10px;display:grid;place-items:center;
  flex:none;background:#7667f820;color:#B8AEFF}
.media-info{min-width:0}
.media-info strong{display:block;font-size:12px;overflow-wrap:anywhere}
.media-info>span{display:block;font-size:10px;color:var(--muted);
  overflow-wrap:anywhere;margin-top:4px}
.share-status{display:flex;flex-direction:column;gap:4px;align-items:flex-start}
.status{font-size:10px;border-radius:6px;padding:3px 7px}
.status-active{color:var(--green);background:#43D6A015}
.status-expired{color:var(--red);background:#F0788915}
.expiry-text{font-size:10px;color:var(--muted);overflow-wrap:anywhere}
.tag{font-size:10px;color:#BBC3D5;background:#252D40;
  border:1px solid #303A52;border-radius:6px;padding:4px 7px;white-space:nowrap}
.tag-password{color:var(--amber);background:#F2BB6210;border-color:#F2BB6230}
.share-link input{width:100%;min-width:0;background:#101625;color:#B6BED1;
  border:1px solid #2B354B;border-radius:7px;padding:8px;font-size:10px}
.share-actions{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
.empty-state{text-align:center;padding:38px 15px;color:var(--muted)}
.empty-icon{font-size:27px;color:#8E81FF;margin-bottom:7px}
.empty-state strong{display:block;color:#D7DCEC;font-size:13px}
.empty-state p{font-size:11px;margin:5px 0 0}
.notice{padding:11px 14px;margin-top:15px;border:1px solid #43D6A044;
  border-radius:9px;background:#43D6A00C;color:var(--green)}
.footer-note{display:flex;gap:12px;align-items:flex-start;margin-top:22px;
  padding:16px;border:1px solid var(--border);border-radius:12px;background:#121929}
.footer-icon{font-size:18px;color:var(--green)}
.footer-note strong{font-size:12px}
.footer-note p{font-size:11px;color:var(--muted);margin:4px 0 0}
.modal{position:fixed;inset:0;z-index:20;background:#050813C9;
  display:flex;align-items:center;justify-content:center;padding:18px;overflow:auto}
.modal-card{width:100%;max-width:570px;background:#171E30;border:1px solid #35405A;
  border-radius:17px;box-shadow:0 25px 90px #0008;overflow:hidden}
.modal-head{display:flex;align-items:center;justify-content:space-between;
  padding:19px 22px;border-bottom:1px solid var(--border)}
.modal-head h2{font-size:17px;margin:0}
.close-btn{border:0;background:transparent;color:var(--muted);font-size:23px}
.modal-body{padding:20px 22px}
.field{margin-bottom:17px}
.field label{display:block;font-size:12px;font-weight:650;margin-bottom:7px}
.field .control{width:100%}
.field-help{font-size:10px;color:var(--muted);margin-top:6px}
.modal-foot{display:flex;justify-content:flex-end;gap:9px;padding:15px 22px;
  border-top:1px solid var(--border)}
.result{font-size:12px;color:var(--green);overflow-wrap:anywhere}
@media(max-width:1200px){
 .main{padding:24px 22px}.sidebar{width:215px}.main{margin-left:215px}
 .share-row{grid-template-columns:minmax(150px,1.3fr) minmax(90px,.7fr)
   minmax(80px,.5fr) minmax(120px,1fr)}
 .share-actions{grid-column:1/-1;padding-left:48px}
}
@media(max-width:850px){
 .sidebar{position:static;width:auto;height:auto;padding:13px 16px;
   flex-direction:row;align-items:center;border-right:0;border-bottom:1px solid var(--border)}
 .brand{padding:0;margin-right:auto}.brand-sub,.nav-label,.sidebar-bottom{display:none}
 .sidebar nav{display:flex;gap:4px}.nav-link{padding:9px}
 .nav-link .nav-icon{width:auto}.nav-link .nav-text{display:none}
 .main{margin-left:0;padding:20px 16px}
 .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
 .share-row{grid-template-columns:minmax(0,1fr) minmax(95px,.6fr)}
 .share-access{display:none}.share-link{grid-column:1/-1}
 .share-actions{grid-column:1/-1;padding-left:0}
}
@media(max-width:520px){
 .brand-name{font-size:13px}.brand-mark{width:34px;height:34px}
 .sidebar{padding:10px}.nav-link{padding:8px}
 .hero{align-items:flex-start;flex-direction:column;padding-top:23px}
 h1{font-size:23px}.stats{gap:9px}.stat{padding:13px}
 .stat-value{font-size:24px}.stat-icon{width:29px;height:29px}
 .section-head{align-items:flex-start;flex-direction:column}
 .search{width:100%}.panel-body{padding:0 12px}
 .share-row{gap:9px}.share-status{font-size:11px}
 .topbar{padding-bottom:15px}
}

/* Movie Share light admin refresh */
:root {
  color-scheme: light;
  --bg:#F3F6FC; --panel:#FFFFFF; --panel2:#F7F9FE;
  --border:#E3E9F3; --primary:#3478F6; --primary2:#7667F8;
  --text:#202B3C; --muted:#7C899E; --green:#159B72;
  --amber:#B87912; --red:#D94F63;
}
body{background:var(--bg);color:var(--text)}
.sidebar{background:#17243A;border-color:#24334C}
.brand-sub,.nav-label{color:#91A0B7}
.nav-link{color:#B8C4D7}
.nav-link:hover{background:#23334D;color:#fff}
.nav-link.active{background:linear-gradient(100deg,#3478F62B,#7667F81C);
  color:#D8E4FF;box-shadow:inset 3px 0 #5B8FF9}
.brand-mark{background:linear-gradient(140deg,#3478F6,#7667F8);
  box-shadow:0 6px 24px #3478F62B}
.service-card{background:#1D2C44;border-color:#30415D}
.service-title{color:#E4EBF7}
.service-sub{color:#AAB8CC}
.main{background:var(--bg)}
.topbar{border-color:var(--border)}
.breadcrumb span{color:#3478F6}
.avatar{background:#E7EEFF;color:#3478F6}
.eyebrow{color:#3478F6}
.btn{background:linear-gradient(105deg,#3478F6,#7667F8)}
.btn:hover{background:linear-gradient(105deg,#2868E3,#6858ED)}
.btn-quiet{background:#F7F9FD;border-color:#DCE4F0;color:#4E5D73}
.btn-quiet:hover{background:#EDF2FB}
.btn-danger{background:#FFF1F2;color:#C83E52;border-color:#F4D4D9}
.btn-danger:hover{background:#FFE4E8}
.stat,.panel{background:#fff;border-color:var(--border);
  box-shadow:0 4px 18px #1E355508}
.control{background:#fff;color:var(--text);border-color:#DCE4F0}
.control:focus{border-color:#3478F6;box-shadow:0 0 0 3px #3478F61C}
.panel-head{border-color:var(--border)}
.file-row{border-color:#EDF0F6}
.file-row:hover{background:#F5F8FF}
.file-type{color:#456ED4;border-color:#D9E4FF;background:#F0F5FF}
.create-strip{background:#F7F9FE;border-top:1px solid var(--border)}
.share-row{border-color:#EDF0F6}
.media-icon{background:#EDF3FF;color:#3478F6}
.share-link input{background:#F7F9FD;color:#52627A;border-color:#E0E7F1}
.status-active{color:#13845F;background:#E7F8F1}
.status-expired{color:#C83E52;background:#FFF0F2}
.tag{color:#65738A;background:#F3F6FA;border-color:#E1E7F0}
.tag-password{color:#9B6811;background:#FFF7E5;border-color:#F3E2B7}
.empty-state strong{color:#344158}
.empty-icon{color:#3478F6}
.notice{border-color:#BCEAD9;background:#F0FBF6;color:#13845F}
.footer-note{background:#fff;border-color:var(--border)}
.footer-icon{color:#159B72}
.settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));
  gap:18px;padding:20px}
.settings-grid .field{margin:0;min-width:0}
.settings-grid .control{width:100%}
.settings-grid .result{grid-column:1/-1;min-height:0}
.settings-panel{overflow:visible}
.create-form{margin:0}
.sticky-create{position:sticky;bottom:0;z-index:4;
  border-top:1px solid var(--border);box-shadow:0 -8px 22px #1E35550A}
.sticky-create .btn{white-space:nowrap}
@media(max-width:850px){
  .settings-grid{grid-template-columns:minmax(0,1fr);gap:14px}
  .settings-grid .result{grid-column:auto}
}
@media(max-width:520px){
  .settings-grid{padding:14px}
  .sticky-create{align-items:stretch;flex-direction:column}
  .sticky-create .btn{width:100%}
}


.settings-overlay[hidden] { display: none !important; }
.settings-overlay {
  position: fixed; inset: 0; z-index: 1000;
  display: flex; align-items: center; justify-content: center;
  padding: 20px; background: rgba(15, 23, 42, .48);
  backdrop-filter: blur(3px);
}
.settings-dialog {
  width: min(100%, 480px); max-height: min(90vh, 720px);
  overflow: auto; background: #fff; color: #172033;
  border: 1px solid #e7ebf3; border-radius: 18px;
  box-shadow: 0 24px 80px rgba(15, 23, 42, .22);
}
.settings-dialog-head {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 16px; padding: 22px 24px 18px; border-bottom: 1px solid #edf0f6;
}
.settings-dialog-body {
  display: grid; gap: 20px; padding: 22px 24px;
}
.settings-dialog-actions {
  display: flex; justify-content: flex-end; gap: 10px;
  padding: 16px 24px 22px; border-top: 1px solid #edf0f6;
}
.settings-dialog .field { min-width: 0; }
.settings-dialog .control { width: 100%; box-sizing: border-box; }
.settings-dialog .result:empty { display: none; }
#settings-x { flex-shrink: 0; }
#create-button:disabled, #confirm-create-button:disabled {
  opacity: .55; cursor: not-allowed;
}
@media (max-width: 520px) {
  .settings-overlay { padding: 12px; align-items: flex-end; }
  .settings-dialog { border-radius: 18px 18px 12px 12px; }
  .settings-dialog-head, .settings-dialog-body { padding-left: 18px; padding-right: 18px; }
  .settings-dialog-actions { padding: 14px 18px 18px; }
}

</style>
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand">
    <div class="brand-mark">M</div>
    <div><div class="brand-name">movie-share</div>
      <div class="brand-sub">PRIVATE MEDIA CLOUD</div></div>
  </div>
  <nav>
    <div class="nav-label">工作台</div>
    <a class="nav-link active" href="#shares"><span class="nav-icon">▤</span><span class="nav-text">分享管理</span></a>
    <a class="nav-link" href="#library"><span class="nav-icon">▧</span><span class="nav-text">媒体库</span></a>
    <a class="nav-link" href="#create" id="nav-create"><span class="nav-icon">＋</span><span class="nav-text">批量分享</span></a>
    <div class="nav-label">系统</div>
    <a class="nav-link" href="#service"><span class="nav-icon">◉</span><span class="nav-text">服务说明</span></a>
  </nav>
  <div class="sidebar-bottom">
    <div class="service-card" id="service">
      <div class="service-title"><span class="service-dot"></span>媒体分享服务</div>
      <div class="service-sub">通过分享链接访问视频</div>
    </div>
  </div>
</aside>

<main class="main">
  <header class="topbar">
    <div class="breadcrumb">工作台　/　<span>分享管理</span></div>
    <div class="top-right"><span>管理控制台</span><div class="avatar">M</div></div>
  </header>

  <section class="hero">
    <div><div class="eyebrow">YOUR MEDIA, YOUR RULES</div>
      <h1>分享管理</h1>
      <div class="subtitle">管理你的媒体分享，轻松把喜欢的视频分享给朋友。</div></div>

  </section>

  __NOTICE__

  <section class="stats">
    <div class="stat"><div class="stat-head"><span class="stat-label">分享总数</span><span class="stat-icon">↗</span></div>
      <div class="stat-value">__TOTAL__</div><div class="stat-foot">全部分享记录，含历史记录</div></div>
    <div class="stat"><div class="stat-head"><span class="stat-label">正在生效</span><span class="stat-icon">✓</span></div>
      <div class="stat-value">__ACTIVE__</div><div class="stat-foot">尚未过期的分享</div></div>
    <div class="stat"><div class="stat-head"><span class="stat-label">即将过期</span><span class="stat-icon">◷</span></div>
      <div class="stat-value">__SOON__</div><div class="stat-foot">未来 7 天内到期</div></div>
    <div class="stat"><div class="stat-head"><span class="stat-label">媒体库文件</span><span class="stat-icon">▧</span></div>
      <div class="stat-value">__FILES__</div><div class="stat-foot">扫描到的 STRM 文件</div></div>
  </section>

<form id="create-form" class="create-form">

  <section class="section" id="library">
    <div class="section-head"><div><div class="section-title">媒体库</div>
      <div class="section-desc">从已扫描的 STRM 文件中选择要分享的内容</div></div>
    </div>
    <div class="panel">
      <div class="panel-head"><span class="panel-caption">STRM 文件列表</span>
        <span class="panel-caption">共 __FILES__ 个文件</span></div>
      <div class="panel-body">
        <div class="file-toolbar">
          <input id="file-search" class="control" type="search" placeholder="搜索文件名或目录">
          <button class="btn btn-small btn-quiet" type="button" onclick="selectVisible(true)">全选当前结果</button>
          <button class="btn btn-small btn-quiet" type="button" onclick="selectVisible(false)">取消选择</button>
          <span id="selected-count" class="selected-count">已选 0 个</span>
        </div>
        <div class="file-list" id="file-list">__FILES_HTML__</div>
      </div>
      <div class="create-strip sticky-create">
        <p>单次最多创建 100 条分享；密码为选填项。</p>
        <button class="btn" id="create-button" type="button" disabled>创建分享（已选 0 个）</button>
      </div>
    </div>
  </section>

  <div class="settings-overlay" id="settings-overlay" hidden>
    <section class="settings-dialog" role="dialog" aria-modal="true"
      aria-labelledby="settings-title">
      <div class="settings-dialog-head">
        <div>
          <div class="section-title" id="settings-title">创建分享</div>
          <div class="section-desc">已选文件将使用以下设置</div>
        </div>
        <button class="btn btn-quiet btn-small" id="settings-x" type="button"
          aria-label="关闭">✕</button>
      </div>
      <div class="settings-dialog-body">
        <div class="field">
          <label for="expiry">分享有效期</label>
          <select id="expiry" class="control">
            <option value="0">永久有效</option>
            <option value="86400">1 天</option>
            <option value="604800">7 天</option>
            <option value="2592000">30 天</option>
          </select>
          <div class="field-help">默认永久有效，不会自动到期。</div>
        </div>
        <div class="field">
          <label for="password">访问密码（选填）</label>
          <input id="password" class="control" type="password"
            placeholder="留空则无需密码" autocomplete="new-password">
          <div class="field-help">设置密码后，访客需要验证才能访问；至少 4 个字符。</div>
        </div>
        <div id="create-result" class="result" role="status" aria-live="polite"></div>
      </div>
      <div class="settings-dialog-actions">
        <button class="btn btn-quiet" id="settings-cancel" type="button">取消</button>
        <button class="btn" id="confirm-create-button" type="submit">确认创建分享</button>
      </div>
    </section>
  </div>

</form>

  <section class="section" id="shares">
    <div class="section-head"><div><div class="section-title">分享记录</div>
      <div class="section-desc">查看链接、有效期和访问权限</div></div>
      <div class="toolbar"><input id="share-search" class="control search" type="search" placeholder="⌕ 搜索名称或目录">
        <button class="btn btn-quiet" type="button" onclick="location.reload()">刷新</button></div>
    </div>
    <div class="panel">
      <div class="panel-head"><span class="panel-caption">全部分享</span>
        <span class="panel-caption">共 __TOTAL__ 条</span></div>
      <div class="panel-body" id="share-list">__SHARES__</div>
    </div>
  </section>

  <div class="footer-note"><div class="footer-icon">◈</div><div>
    <strong>媒体传输与隐私</strong>
    <p>默认不设置访问密码。播放地址由服务端按需获取，浏览器获得实际播放地址后直接请求媒体源；实际传输路径仍取决于 SmartStrm 和上游服务。</p>
  </div></div>
</main>
</div>


<script>
const API_BASE = '/api/__ADMIN_TOKEN__';

function visibleFiles() {
  return Array.from(document.querySelectorAll('.file-item'))
    .filter(el => el.style.display !== 'none');
}
function updateCount() {
  const count = document.querySelectorAll('.file-check:checked').length;
  document.getElementById('selected-count').textContent = '已选 ' + count + ' 个';
  const button = document.getElementById('create-button');
  button.textContent = '创建分享（已选 ' + count + ' 个）';
  button.disabled = count === 0;
  const confirmButton = document.getElementById('confirm-create-button');
  if (confirmButton && !document.getElementById('create-result').textContent.includes('正在创建')) {
    confirmButton.disabled = count === 0;
  }
}
function selectVisible(checked) {
  visibleFiles().forEach(el => {
    const box = el.querySelector('.file-check');
    if (box) box.checked = checked;
  });
  updateCount();
}
document.getElementById('file-search').addEventListener('input', function() {
  const q = this.value.trim().toLocaleLowerCase();
  document.querySelectorAll('.file-item').forEach(el => {
    el.style.display = el.dataset.search.includes(q) ? '' : 'none';
  });
});
document.getElementById('file-list').addEventListener('change', updateCount);
document.getElementById('share-search').addEventListener('input', function() {
  const q = this.value.trim().toLocaleLowerCase();
  document.querySelectorAll('#share-list .share-row').forEach(el => {
    el.style.display = el.dataset.search.includes(q) ? '' : 'none';
  });
});
function openCreate() {
  if (!document.querySelector('.file-check:checked')) {
    alert('请先在媒体库选择至少一个 STRM 文件。');
    return;
  }
  const overlay = document.getElementById('settings-overlay');
  overlay.hidden = false;
  document.getElementById('create-result').textContent = '';
  document.getElementById('confirm-create-button').disabled = false;
  document.getElementById('expiry').focus({preventScroll:true});
}
function closeCreateSettings() {
  document.getElementById('settings-overlay').hidden = true;
}
document.getElementById('nav-create').addEventListener('click', function(e) {
  e.preventDefault();
  document.getElementById('library').scrollIntoView({behavior:'smooth', block:'start'});
});
document.getElementById('create-button').addEventListener('click', openCreate);
document.getElementById('settings-x').addEventListener('click', closeCreateSettings);
document.getElementById('settings-cancel').addEventListener('click', closeCreateSettings);
document.getElementById('settings-overlay').addEventListener('click', function(e) {
  if (e.target === this) closeCreateSettings();
});
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeCreateSettings();
});
async function copyLink(button) {
  const row = button.closest('.share-row');
  const input = row && row.querySelector('.share-link input');
  if (!input) return;
  try {
    await navigator.clipboard.writeText(input.value);
    button.textContent = '已复制';
    setTimeout(() => button.textContent = '复制链接', 1400);
  } catch (e) {
    input.focus();
    input.select();
    alert('浏览器不允许自动复制，请手动复制选中的链接。');
  }
}
async function revokeShare(button) {
  const token = button.dataset.token;
  if (!confirm('确定撤销这条分享吗？撤销后对应分享链接将失效。')) return;
  button.disabled = true;
  try {
    const response = await fetch(API_BASE + '/revoke', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: token})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '撤销失败');
    location.reload();
  } catch (e) {
    alert(e.message || '撤销失败');
    button.disabled = false;
  }
}
document.getElementById('create-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  const paths = Array.from(document.querySelectorAll('.file-check:checked'))
    .map(box => box.value);
  if (!paths.length) {
    alert('请先在媒体库选择至少一个 STRM 文件。');
    document.getElementById('file-search').focus();
    return;
  }
  if (paths.length > 100) {
    alert('单次最多创建 100 个分享，请分批操作。');
    return;
  }
  const password = document.getElementById('password').value;
  if (password && password.length < 4) {
    alert('密码至少需要 4 个字符。');
    return;
  }
  const button = document.getElementById('confirm-create-button');
  const result = document.getElementById('create-result');
  button.disabled = true;
  result.textContent = '正在创建，请稍候……';
  try {
    const response = await fetch(API_BASE + '/create', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        paths: paths,
        expiry_seconds: Number(document.getElementById('expiry').value),
        password: password
      })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '创建失败');
    const created = data.created || [];
    const failed = data.failed || [];
    let message = '创建成功 ' + created.length + ' 条';
    if (failed.length) message += '，失败 ' + failed.length + ' 条';
    result.textContent = message;
    if (failed.length) {
      result.textContent += '：' + failed.map(x => x.path + '（' + x.error + '）').join('；');
    }
    if (created.length) {
      result.textContent += '。页面即将刷新。';
      setTimeout(() => location.reload(), 1300);
    }
  } catch (e) {
    result.textContent = '创建失败：' + (e.message || '未知错误');
  } finally {
    if (result.textContent.includes('页面即将刷新')) {
      button.disabled = true;
    } else {
      updateCount();
    }
  }
});
updateCount();
</script>
</body>
</html>"""

    html = html.replace("__NOTICE__", notice_html)
    html = html.replace("__TOTAL__", str(len(shares)))
    html = html.replace("__ACTIVE__", str(active_count))
    html = html.replace("__SOON__", str(soon_count))
    html = html.replace("__FILES__", str(len(files)))
    html = html.replace("__SHARES__", share_html)
    html = html.replace("__FILES_HTML__", file_html)
    html = html.replace("__ADMIN_TOKEN__", quote(ADMIN_TOKEN, safe=""))
    return html


class Handler(BaseHTTPRequestHandler):
    server_version = "MovieShare/2.0"
    sys_version = ""

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.client_address[0], fmt % args)

    def send_bytes(self, status, body, content_type="text/html; charset=utf-8",
                   headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")

        for key, value in (headers or {}).items():
            self.send_header(key, value)

        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, status, data):
        self.send_bytes(
            status,
            json.dumps(data, ensure_ascii=False),
            "application/json; charset=utf-8"
        )

    def redirect(self, location, status=302, headers=None):
        out = {"Location": location}
        if headers:
            out.update(headers)
        self.send_bytes(status, b"", headers=out)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("请求长度无效")

        if length <= 0 or length > MAX_BODY:
            raise ValueError("请求内容为空或超过大小限制")

        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("JSON 格式错误")

        if not isinstance(data, dict):
            raise ValueError("请求内容必须是 JSON 对象")

        return data

    def admin_authorized(self):
        prefix = "/manage/"
        path = urlparse(self.path).path

        if not path.startswith(prefix):
            return False

        supplied = path[len(prefix):]
        return bool(ADMIN_TOKEN) and hmac.compare_digest(
            supplied, ADMIN_TOKEN
        )

    def share_access(self, token):
        data, record = find_share(token)

        if not isinstance(record, dict):
            self.send_bytes(
                404,
                page_template("分享不存在", "<h1>分享不存在或已撤销</h1>")
            )
            return None, None

        if share_expired(record):
            self.send_bytes(
                410,
                page_template("分享已过期", "<h1>此分享已过期</h1>")
            )
            return None, None

        return data, record

    def share_requires_password(self, token, record):
        if is_unlocked(self, token, record):
            return False

        body = render_password_page(token, get_share_title(record))
        self.send_bytes(401, body)
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            self.send_bytes(
                200,
                '{"status":"ok"}',
                "application/json; charset=utf-8"
            )
            return

        # 后台管理页面
        if path.startswith("/manage/"):
            if not self.admin_authorized():
                self.send_bytes(
                    403,
                    page_template("无权访问", "<h1>无权访问管理页面</h1>")
                )
                return

            self.send_bytes(200, admin_page(self))
            return

        # 兼容旧版本固定分享链接
        if SHARE_TOKEN and path in (
            "/" + SHARE_TOKEN,
            "/" + SHARE_TOKEN + "/"
        ):
            legacy_record = {
                "title": os.environ.get("VIDEO_TITLE", "视频分享"),
                "url": os.environ.get("VIDEO_URL", "")
            }
            self.send_bytes(
                200,
                video_page(get_share_title(legacy_record), "/" + SHARE_TOKEN + "/play-url")
            )
            return

        if SHARE_TOKEN and path == "/" + SHARE_TOKEN + "/play-url":
            video_url = os.environ.get("VIDEO_URL", "").strip()
            if not video_url:
                self.send_json(500, {"error": "未配置旧版视频地址"})
                return

            try:
                direct_url = get_play_url(video_url, self.headers.get("User-Agent", ""))
                self.send_json(200, {"url": direct_url})
            except Exception:
                logging.exception("旧版播放地址获取失败")
                self.send_json(502, {"error": "获取播放地址失败，请稍后重试"})
            return

        # 新版及旧记录分享链接
        match = re.fullmatch(r"/s/([A-Za-z0-9_-]{12,100})(?:/(play-url))?", path)
        if match:
            token = match.group(1)
            endpoint = match.group(2)

            data, record = self.share_access(token)
            if record is None:
                return

            if endpoint == "play-url":
                if self.share_requires_password(token, record):
                    return

                source_url = get_share_url(record)

                if not source_url:
                    try:
                        source_url = read_strm(get_share_path(record))
                    except Exception:
                        logging.exception("读取 STRM 失败")
                        self.send_json(404, {"error": "找不到对应的 STRM 文件"})
                        return

                try:
                    direct_url = get_play_url(
                        source_url, self.headers.get("User-Agent", "")
                    )
                    self.send_json(200, {"url": direct_url})
                except Exception:
                    logging.exception("获取 SmartStrm 跳转地址失败")
                    self.send_json(502, {"error": "获取播放地址失败，请稍后重试"})
                return

            if self.share_requires_password(token, record):
                return

            self.send_bytes(
                200,
                video_page(
                    get_share_title(record),
                    "/s/" + quote(token) + "/play-url"
                )
            )
            return

        self.send_bytes(
            404,
            page_template("页面不存在", "<h1>页面不存在</h1>")
        )

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 分享密码验证
        match = re.fullmatch(r"/s/([A-Za-z0-9_-]{12,100})/unlock", path)
        if match:
            token = match.group(1)
            data, record = self.share_access(token)
            if record is None:
                return

            if not share_password_enabled(record):
                self.redirect("/s/" + quote(token))
                return

            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 16384:
                    raise ValueError("请求内容无效")

                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                form = parse_qs(raw, keep_blank_values=True)
                password = form.get("password", [""])[0]
            except Exception:
                self.send_bytes(400, "请求格式错误", "text/plain; charset=utf-8")
                return

            if not verify_password(password, record.get("password_hash", "")):
                self.send_bytes(
                    401,
                    render_password_page(
                        token, get_share_title(record), "密码错误，请重新输入。"
                    )
                )
                return

            expires = now_ts() + COOKIE_HOURS * 3600
            share_exp = record.get("expires_at")
            if share_exp:
                expires = min(expires, int(share_exp))

            value = make_cookie_value(token, expires)
            proto = self.headers.get("X-Forwarded-Proto", "").lower()
            secure = "; Secure" if proto == "https" else ""

            cookie_header = (
                cookie_name(token) + "=" + value +
                "; Path=/s/" + quote(token) +
                "; Max-Age=" + str(max(0, expires - now_ts())) +
                "; HttpOnly; SameSite=Lax" + secure
            )

            self.redirect(
                "/s/" + quote(token),
                headers={"Set-Cookie": cookie_header}
            )
            return

        # 以下接口只允许后台管理令牌访问
        if not path.startswith("/api/"):
            self.send_bytes(404, "Not found", "text/plain; charset=utf-8")
            return

        prefix = "/api/" + ADMIN_TOKEN + "/"
        if not ADMIN_TOKEN or not path.startswith(prefix):
            self.send_json(403, {"error": "无权访问"})
            return

        action = path[len(prefix):]

        try:
            payload = self.read_json()
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
            return

        if action == "create":
            self.create_shares(payload)
            return

        if action == "revoke":
            self.revoke_share(payload)
            return

        self.send_json(404, {"error": "未知接口"})

    def create_shares(self, payload):
        paths = payload.get("paths")

        # 兼容旧版单条创建接口
        if paths is None and payload.get("path"):
            paths = [payload.get("path")]

        if not isinstance(paths, list) or not paths:
            self.send_json(400, {"error": "请至少选择一个 STRM 文件"})
            return

        if len(paths) > MAX_BATCH:
            self.send_json(400, {"error": "单次最多创建 100 个分享"})
            return

        expiry_seconds = payload.get("expiry_seconds", 0)
        try:
            expiry_seconds = int(expiry_seconds)
        except (TypeError, ValueError):
            self.send_json(400, {"error": "有效期参数无效"})
            return

        allowed_expiries = (0, 86400, 604800, 2592000)
        if expiry_seconds not in allowed_expiries:
            self.send_json(400, {"error": "有效期只能选择永久、1 天、7 天或 30 天"})
            return

        password = str(payload.get("password") or "")
        if password and len(password) < 4:
            self.send_json(400, {"error": "密码至少需要 4 个字符"})
            return
        if len(password) > 256:
            self.send_json(400, {"error": "密码不能超过 256 个字符"})
            return

        shares = load_shares()
        created = []
        failed = []
        seen = set()

        for raw_path in paths:
            try:
                rel_path = str(raw_path or "").replace("\\", "/").strip()

                if rel_path in seen:
                    raise ValueError("本次选择中存在重复路径")
                seen.add(rel_path)

                full = resolve_strm(rel_path)
                # 先验证文件确实含有有效地址
                source_url = read_strm(rel_path)

                token = secrets.token_urlsafe(18)
                while token in shares:
                    token = secrets.token_urlsafe(18)

                now = now_ts()
                title = full.stem

                record = {
                    "path": rel_path,
                    "title": title,
                    "created_at": now
                }

                # 新记录默认不保存 STRM 内的实际播放地址，
                # 播放时重新读取文件并向 SmartStrm 获取跳转地址。
                if password:
                    record["password_hash"] = hash_password(password)

                if expiry_seconds:
                    record["expires_at"] = now + expiry_seconds

                shares[token] = record

                created.append({
                    "token": token,
                    "title": title,
                    "path": rel_path,
                    "url": public_base_url(self) + "/s/" + quote(token),
                    "expires_at": record.get("expires_at"),
                    "password_enabled": bool(password)
                })

            except Exception as exc:
                failed.append({
                    "path": str(raw_path),
                    "error": str(exc)
                })

        try:
            save_shares(shares)
        except Exception:
            logging.exception("保存分享记录失败")
            self.send_json(500, {"error": "保存分享记录失败，未能完成创建"})
            return

        self.send_json(200, {"created": created, "failed": failed})

    def revoke_share(self, payload):
        token = str(payload.get("token") or "").strip()

        if not re.fullmatch(r"[A-Za-z0-9_-]{12,100}", token):
            self.send_json(400, {"error": "分享令牌格式无效"})
            return

        shares = load_shares()
        if token not in shares:
            self.send_json(404, {"error": "分享记录不存在"})
            return

        del shares[token]

        try:
            save_shares(shares)
        except Exception:
            logging.exception("撤销分享保存失败")
            self.send_json(500, {"error": "保存失败，撤销未完成"})
            return

        self.send_json(200, {"ok": True})


def video_page(title, endpoint):
    safe_title = esc(title)
    safe_endpoint = json.dumps(endpoint)

    body = """
<h1>{title}</h1>
<style>#center-play[hidden]{{display:none !important;}}</style>
<div style="position:relative;width:100%;aspect-ratio:16/9;min-height:220px;max-height:70vh;background:#000;border-radius:10px;overflow:hidden;display:flex;align-items:center;justify-content:center">
  <video id="video" controls playsinline preload="metadata" hidden
         style="width:100%;height:100%;max-height:70vh;object-fit:contain;background:#000"></video>
  <button id="center-play" type="button"
          style="position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:76px;height:76px;border-radius:50%;padding:0;font-size:28px;background:#1769d2;color:#fff;border:0;cursor:pointer"
          aria-label="播放视频">▶</button>
</div>
<div class="actions">
  <button id="play" type="button">播放</button>
  <button id="download" class="secondary" type="button">下载视频</button>
</div>
<p id="status" class="muted">点击播放后获取最新的视频地址。</p>
<script>
const endpoint = {endpoint};
const video = document.getElementById('video');
const centerPlay = document.getElementById('center-play');
const playButton = document.getElementById('play');
const downloadButton = document.getElementById('download');
const statusBox = document.getElementById('status');
let directUrl = '';

async function getUrl() {{
  const response = await fetch(endpoint + (endpoint.includes('?') ? '&' : '?') + 'ts=' + Date.now(), {{cache: 'no-store'}});
  if (response.status === 401) {{
    location.reload();
    throw new Error('请先验证分享密码');
  }}
  const data = await response.json();
  if (!response.ok || !data.url) {{
    throw new Error(data.error || '获取播放地址失败，HTTP ' + response.status);
  }}
  directUrl = data.url;
  return directUrl;
}}

async function startPlayback() {{
  centerPlay.disabled = true;
  playButton.disabled = true;
  statusBox.textContent = video.src ? '正在继续播放……' : '正在获取播放地址……';

  try {{
    if (!video.src) {{
      const url = await getUrl();
      video.src = url;
      video.hidden = false;
      video.load();
    }}
    await video.play();
    statusBox.textContent = '正在播放。视频由上游 CDN 提供。';
  }} catch (e) {{
    centerPlay.hidden = false;
    statusBox.textContent = '播放失败：' + (e.message || '未知错误');
  }} finally {{
    centerPlay.disabled = false;
    playButton.disabled = false;
  }}
}}

centerPlay.addEventListener('click', startPlayback);
playButton.addEventListener('click', startPlayback);

video.addEventListener('playing', () => {{
  centerPlay.hidden = true;
  statusBox.textContent = '正在播放。视频由上游 CDN 提供。';
}});

video.addEventListener('pause', () => {{
  if (video.currentTime > 0 && !video.ended) {{
    centerPlay.hidden = false;
  }}
}});

video.addEventListener('ended', () => {{
  centerPlay.hidden = false;
  statusBox.textContent = '播放结束。';
}});

video.addEventListener('waiting', () => {{
  statusBox.textContent = '正在等待视频数据……';
}});

video.addEventListener('error', () => {{
  const err = video.error;
  const messages = {{
    1: '播放已中止',
    2: '网络错误：视频数据获取失败',
    3: '视频解码失败或格式不受支持',
    4: '视频格式或视频地址不受支持'
  }};
  centerPlay.hidden = false;
  statusBox.textContent = '播放失败：' +
    (err ? (messages[err.code] || ('媒体错误 ' + err.code)) : '未知错误') +
    '。请检查浏览器 Network 中的 CDN 请求状态。';
}});

downloadButton.addEventListener('click', async () => {{
  downloadButton.disabled = true;
  statusBox.textContent = '正在获取下载地址……';
  try {{
    const url = await getUrl();
    window.open(url, '_blank', 'noopener');
    statusBox.textContent = '已打开上游下载地址；实际下载行为取决于 CDN 响应。';
  }} catch (e) {{
    statusBox.textContent = e.message || '获取下载地址失败';
  }} finally {{
    downloadButton.disabled = false;
  }}
}});
</script>
""".format(title=safe_title, endpoint=safe_endpoint)

    return page_template(title, body)


if __name__ == "__main__":
    if not SHARE_TOKEN:
        logging.warning("环境变量 SHARE_TOKEN 未设置")
    if not ADMIN_TOKEN:
        logging.warning("环境变量 ADMIN_TOKEN 未设置")

    logging.info("Movie Share listening on %s:%s", HOST, PORT)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()
