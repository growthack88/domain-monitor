#!/usr/bin/env python3
"""
Domain uptime + SSL monitor — Cloudflare-Worker-aware (Lovable proxy methodology).

Background: Lovable's custom-domain edge (185.158.133.1) is unreachable from some
regions, and Lovable auto-disconnects any domain whose A record isn't that IP. So
the fix is a Cloudflare Worker ("lovable-proxy") that proxies each custom domain to
its <project>.lovable.app subdomain and stamps an `x-proxy: lovable-worker` header.

This monitor therefore checks, per domain in domains.txt:
  1. HTTP(S) reachability + the actual page body (catches "domain not connected" /
     "project not found" pages that still return 2xx/421).
  2. For domains listed in worker_map.json: that they are actually served *via the
     Worker* (x-proxy header present) and not the loop-guard placeholder, and
     optionally that the page contains an expected marker (catches WRONG project /
     a stranger's same-named *.lovable.app).
  3. TLS certificate validity + days to expiry.

States (worst first): DOWN, WRONG_PROJECT, SSL_INVALID, NEEDS_ACTION (loop-guard),
SSL_EXPIRING, AT_RISK (Lovable domain not on the Worker → will disconnect), DEGRADED, OK.

Alerting: Slack live on state change; Pushover one digest/day (instant on manual run).
"""

import os
import ssl
import json
import socket
import re
import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import requests

# ----------------------------- config -----------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
DOMAINS_FILE = os.path.join(ROOT, "domains.txt")
WORKER_MAP_FILE = os.path.join(ROOT, "worker_map.json")
DOCS_DIR = os.path.join(ROOT, "docs")
STATE_FILE = os.path.join(ROOT, "state.json")
STATUS_FILE = os.path.join(DOCS_DIR, "status.json")
DASHBOARD_FILE = os.path.join(DOCS_DIR, "index.html")

SSL_WARN_DAYS = int(os.environ.get("SSL_WARN_DAYS", "14"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "20"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "12"))
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").strip()

PUSHOVER_TOKEN = os.environ.get("PUSHOVER_TOKEN", "").strip()
PUSHOVER_USER = os.environ.get("PUSHOVER_USER", "").strip()
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "").strip()

WORKER_PROXY_HEADER = "x-proxy"          # set by the lovable-proxy Worker
WORKER_PROXY_VALUE = "lovable-worker"    # value when correctly proxied

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
}


def load_worker_map():
    """domain -> {"sub": <project subdomain>, "expect": <optional substring>}."""
    out = {}
    try:
        with open(WORKER_MAP_FILE, encoding="utf-8") as f:
            raw = json.load(f).get("map", {})
        for dom, val in raw.items():
            if isinstance(val, dict):
                out[dom.lower()] = {"sub": val.get("sub", ""), "expect": (val.get("expect") or "").lower()}
            else:
                out[dom.lower()] = {"sub": str(val), "expect": ""}
    except Exception as e:  # noqa: BLE001
        print("worker_map.json not loaded:", e)
    return out


WORKER_MAP = load_worker_map()


# ----------------------------- checks -----------------------------
def load_domains():
    domains = []
    with open(DOMAINS_FILE, encoding="utf-8") as f:
        for line in f:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            d = d.replace("https://", "").replace("http://", "").strip("/")
            d = d.split("/")[0].split(",")[0].split("|")[0].strip()
            if d:
                domains.append(d)
    seen, out = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def check_ssl(host, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        days_left = (expires - dt.datetime.now(dt.timezone.utc)).days
        return {"ok": True, "days_left": days_left, "expires": expires.strftime("%Y-%m-%d"), "error": None}
    except ssl.SSLCertVerificationError as e:
        msg = getattr(e, "verify_message", None) or str(e)
        return {"ok": False, "days_left": None, "expires": None, "error": f"invalid cert: {msg}"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "days_left": None, "expires": None, "error": "TLS timeout"}
    except socket.gaierror:
        return {"ok": False, "days_left": None, "expires": None, "error": "DNS resolution failed"}
    except ConnectionRefusedError:
        return {"ok": False, "days_left": None, "expires": None, "error": "connection refused (no 443)"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "days_left": None, "expires": None, "error": f"TLS error: {e}"}


# Pages that return a "success-ish" status but mean the domain is NOT live.
BROKEN_PAGE_SIGNATURES = [
    ("are not properly configured", "Lovable: domain/DNS not connected"),
    ("project not found", "Lovable: project not found (not migrated / disconnected)"),
    ("deployment_not_found", "Vercel: deployment not found"),
    ("the deployment could not be found", "Vercel: deployment not found"),
    ("there isn't a github pages site here", "GitHub Pages: no site here"),
    ("site not found · netlify", "Netlify: site not found"),
    ("sorry, this shop is currently unavailable", "Shopify: shop unavailable"),
    ("no such app", "Host: no such app"),
]
# The Worker's own loop-guard placeholder (project's *.lovable.app redirects to the
# custom domain). Needs a Lovable-side fix, not a Cloudflare one.
LOOPGUARD_SIGNATURE = "this site is being configured"


def detect_broken_page(body_lower):
    for sig, reason in BROKEN_PAGE_SIGNATURES:
        if sig in body_lower:
            return reason
    return None


def page_title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return (m.group(1).strip()[:80] if m else "")


def check_http(domain):
    url = f"https://{domain}"
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True, headers=BROWSER_HEADERS)
        code = r.status_code
        try:
            body = (r.text or "")[:8000]
        except Exception:  # noqa: BLE001
            body = ""
        body_lower = body.lower()
        return {
            "code": code,
            "final_url": r.url,
            "server": r.headers.get("Server", ""),
            "x_proxy": r.headers.get(WORKER_PROXY_HEADER, "").lower(),
            "title": page_title(body),
            "body_lower": body_lower,
            "time_ms": int(r.elapsed.total_seconds() * 1000),
            "error": None,
        }
    except requests.exceptions.SSLError as e:
        return _httperr(url, f"TLS handshake failed: {str(e)[:160]}")
    except requests.exceptions.ConnectTimeout:
        return _httperr(url, "connect timeout")
    except requests.exceptions.ReadTimeout:
        return _httperr(url, "read timeout")
    except requests.exceptions.ConnectionError as e:
        return _httperr(url, f"connection error: {str(e)[:160]}")
    except Exception as e:  # noqa: BLE001
        return _httperr(url, str(e)[:160])


def _httperr(url, msg):
    return {"code": None, "final_url": url, "server": "", "x_proxy": "", "title": "",
            "body_lower": "", "time_ms": None, "error": msg}


def guess_host(http):
    s = (http.get("server") or "").lower()
    u = (http.get("final_url") or "").lower()
    if http.get("x_proxy") == WORKER_PROXY_VALUE:
        return "Cloudflare Worker"
    if "myshopify" in u or "shopify" in s:
        return "Shopify"
    if "lovable" in u or "lovable" in s:
        return "Lovable"
    if "vercel" in s or "vercel" in u:
        return "Vercel"
    if "netlify" in s or "netlify" in u:
        return "Netlify"
    if "github.io" in u or "github" in s:
        return "GitHub Pages"
    if "cloudflare" in s:
        return "Cloudflare"
    if "litespeed" in s or "apache" in s or "nginx" in s:
        return "Shared/WordPress"
    return s[:24] if s else "—"


def evaluate(domain):
    http = check_http(domain)
    sslr = check_ssl(domain)
    wm = WORKER_MAP.get(domain)            # this domain SHOULD be served via the Worker
    code = http["code"]
    body_lower = http.get("body_lower", "")

    status = "OK"
    reason = None

    # --- reachability / page health ---
    if http["error"]:
        status, reason = "DOWN", http["error"]
    elif LOOPGUARD_SIGNATURE in body_lower or (code == 503 and http.get("x_proxy")):
        sub = wm["sub"] if wm else "the project"
        status, reason = "NEEDS_ACTION", f"Worker loop-guard — remove this domain in Lovable project '{sub}' (stops its *.lovable.app redirect)"
    else:
        broken = detect_broken_page(body_lower)
        if broken:
            status, reason = "DOWN", broken
        elif code == 421:
            status, reason = "DOWN", "HTTP 421 — not connected to a project"
        elif code is not None and code >= 500:
            status, reason = "DOWN", f"HTTP {code}"
        elif code in (401, 403, 429):
            status = "OK"                  # alive, just bot-gated
        elif code is not None and 400 <= code < 500:
            status, reason = "DEGRADED", f"HTTP {code}"
        elif code is not None and code < 400:
            status = "OK"

    # --- Worker methodology checks (only for mapped Lovable domains that are reachable) ---
    if status == "OK" and wm:
        if http.get("x_proxy") != WORKER_PROXY_VALUE:
            # loads, but NOT through the Worker → still on old orange/185 path; Lovable will disconnect it.
            status, reason = "AT_RISK", "served but NOT via the Worker — migrate to lovable-proxy (will disconnect)"
        elif wm["expect"] and wm["expect"] not in body_lower and wm["expect"] not in (http.get("title") or "").lower():
            # served via Worker but content doesn't match the expected project → WRONG project / stranger subdomain.
            status, reason = "WRONG_PROJECT", f"served via Worker but expected marker not found — check map: {domain} -> {wm['sub']}.lovable.app"

    ssl_invalid = not sslr["ok"]
    ssl_expiring = sslr["ok"] and sslr["days_left"] is not None and sslr["days_left"] <= SSL_WARN_DAYS

    # --- overall severity ---
    if status in ("DOWN", "WRONG_PROJECT"):
        overall = status
    elif ssl_invalid:
        overall = "SSL_INVALID"
    elif status == "NEEDS_ACTION":
        overall = "NEEDS_ACTION"
    elif ssl_expiring:
        overall = "SSL_EXPIRING"
    elif status == "AT_RISK":
        overall = "AT_RISK"
    elif status == "DEGRADED":
        overall = "DEGRADED"
    else:
        overall = "OK"

    return {
        "domain": domain,
        "overall": overall,
        "reason": reason,
        "on_worker": bool(wm),
        "worker_sub": wm["sub"] if wm else "",
        "via_worker": http.get("x_proxy") == WORKER_PROXY_VALUE,
        "down": overall in ("DOWN", "WRONG_PROJECT"),
        "ssl_invalid": ssl_invalid,
        "ssl_expiring": ssl_expiring,
        "http": {k: http[k] for k in ("code", "final_url", "server", "x_proxy", "title", "time_ms", "error")},
        "ssl": sslr,
        "host": guess_host(http),
    }


# ----------------------------- alerting -----------------------------
SEV_ORDER = {"DOWN": 0, "WRONG_PROJECT": 1, "SSL_INVALID": 2, "NEEDS_ACTION": 3,
             "SSL_EXPIRING": 4, "AT_RISK": 5, "DEGRADED": 6, "OK": 7}
SEV_EMOJI = {"DOWN": "🔴", "WRONG_PROJECT": "🟣", "SSL_INVALID": "🔒", "NEEDS_ACTION": "🔁",
             "SSL_EXPIRING": "⚠️", "AT_RISK": "🟠", "DEGRADED": "🟡", "OK": "✅"}


def state_signature(r):
    # include the overall state so transitions between AT_RISK/NEEDS_ACTION/etc. alert too
    return f"{r['overall']}"


def problem_line(r):
    d, ov = r["domain"], r["overall"]
    em = SEV_EMOJI.get(ov, "•")
    if ov == "OK":
        return f"✅ {d}"
    if ov == "SSL_EXPIRING":
        return f"{em} {d} — SSL expires in {r['ssl']['days_left']}d ({r['ssl']['expires']})"
    if ov == "SSL_INVALID":
        return f"{em} {d} — SSL INVALID ({r['ssl']['error']})"
    return f"{em} {d} — {ov} ({r.get('reason') or r['http'].get('error') or r['http'].get('code')})"


def send_pushover(title, message, priority=1):
    if not (PUSHOVER_TOKEN and PUSHOVER_USER):
        return
    payload = {"token": PUSHOVER_TOKEN, "user": PUSHOVER_USER, "title": title[:250],
               "message": message[:1024], "priority": priority, "html": 1}
    if DASHBOARD_URL:
        payload["url"] = DASHBOARD_URL
        payload["url_title"] = "Open dashboard"
    if priority >= 2:
        payload["retry"] = 60
        payload["expire"] = 3600
    try:
        requests.post("https://api.pushover.net/1/messages.json", data=payload, timeout=15)
    except Exception as e:  # noqa: BLE001
        print("Pushover send failed:", e)


def send_slack(text):
    if not SLACK_WEBHOOK_URL:
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=15)
    except Exception as e:  # noqa: BLE001
        print("Slack send failed:", e)


def send_alerts(new_problems, recovered):
    if not new_problems and not recovered:
        return
    lines = []
    if new_problems:
        lines.append("*New issues:*")
        lines += [problem_line(r) for r in sorted(new_problems, key=lambda r: SEV_ORDER.get(r["overall"], 9))]
    if recovered:
        lines.append("")
        lines.append("*Recovered:*")
        lines += [f"✅ {r['domain']} back to normal" for r in recovered]
    body = "\n".join(lines)
    if DASHBOARD_URL:
        body += f"\n\nDashboard: {DASHBOARD_URL}"
    send_slack(body)


def send_pushover_daily_digest(results, checked_at):
    problems = [r for r in results if r["overall"] != "OK"]
    if not problems:
        return
    lines = [f"{len(problems)} domain issue(s) — {checked_at}", ""]
    lines += [problem_line(r) for r in sorted(problems, key=lambda r: SEV_ORDER.get(r["overall"], 9))]
    send_pushover(f"🔴 {len(problems)} domain issue(s)", "\n".join(lines), priority=1)


def send_status_summary(results, checked_at):
    counts = {}
    for r in results:
        counts[r["overall"]] = counts.get(r["overall"], 0) + 1
    problems = [r for r in results if r["overall"] != "OK"]
    header = (f"*Domain check — {checked_at}*\n"
              f"{counts.get('OK',0)} OK · {counts.get('DOWN',0)} down · "
              f"{counts.get('WRONG_PROJECT',0)} wrong-project · {counts.get('NEEDS_ACTION',0)} needs-action · "
              f"{counts.get('AT_RISK',0)} at-risk · {counts.get('SSL_INVALID',0)} SSL invalid · "
              f"{counts.get('SSL_EXPIRING',0)} SSL expiring · {counts.get('DEGRADED',0)} degraded")
    if problems:
        lines = [header, ""] + [problem_line(r) for r in sorted(problems, key=lambda r: SEV_ORDER.get(r["overall"], 9))]
    else:
        lines = [header, "", "✅ All domains healthy."]
    body = "\n".join(lines)
    if DASHBOARD_URL:
        body += f"\n\nDashboard: {DASHBOARD_URL}"
    send_slack(body)
    send_pushover("Domain check", body.replace("*", ""), priority=0)


# ----------------------------- dashboard -----------------------------
SEV_COLOR = {"DOWN": "#ef4444", "WRONG_PROJECT": "#a855f7", "SSL_INVALID": "#ef4444",
             "NEEDS_ACTION": "#3b82f6", "SSL_EXPIRING": "#f59e0b", "AT_RISK": "#f59e0b",
             "DEGRADED": "#f59e0b", "OK": "#22c55e"}
SEV_LABEL = {"DOWN": "DOWN", "WRONG_PROJECT": "WRONG PROJECT", "SSL_INVALID": "SSL INVALID",
             "NEEDS_ACTION": "NEEDS ACTION", "SSL_EXPIRING": "SSL EXPIRING",
             "AT_RISK": "AT RISK", "DEGRADED": "DEGRADED", "OK": "OK"}
SEV_BADGE_CLASS = {"DOWN": "b-down", "WRONG_PROJECT": "b-wrong", "SSL_INVALID": "b-sslbad",
                   "NEEDS_ACTION": "b-act", "SSL_EXPIRING": "b-warn", "AT_RISK": "b-risk",
                   "DEGRADED": "b-degraded", "OK": "b-ok"}


DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Monitor — Live Status</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>
  :root {{
    color-scheme: dark;
    --bg: #0a0d14;
    --bg-elev: #131826;
    --bg-elev-2: #1a2033;
    --border: #1f2638;
    --border-strong: #2a3349;
    --text: #e8ecf3;
    --text-muted: #8b94a8;
    --text-dim: #5d6580;
    --accent: #6366f1;
    --accent-2: #8b5cf6;
    --green: #22c55e;
    --green-soft: rgba(34, 197, 94, 0.12);
    --red: #ef4444;
    --red-soft: rgba(239, 68, 68, 0.12);
    --amber: #f59e0b;
    --amber-soft: rgba(245, 158, 11, 0.12);
    --blue: #3b82f6;
    --blue-soft: rgba(59, 130, 246, 0.12);
    --purple: #a855f7;
    --purple-soft: rgba(168, 85, 247, 0.12);
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ height: 100%; }}
  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    background: var(--bg);
    background-image:
      radial-gradient(circle at 15% -5%, rgba(99, 102, 241, 0.18) 0%, transparent 40%),
      radial-gradient(circle at 85% -5%, rgba(139, 92, 246, 0.12) 0%, transparent 40%);
    background-attachment: fixed;
    color: var(--text);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 1280px; margin: 0 auto; padding: 32px 24px 64px; }}

  /* Header */
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 28px; gap: 20px; flex-wrap: wrap; }}
  .title-block h1 {{
    font-size: 30px; font-weight: 800; margin: 0 0 8px; letter-spacing: -0.025em;
    background: linear-gradient(135deg, #ffffff 0%, #94a3b8 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
  }}
  .meta {{ color: var(--text-muted); font-size: 13.5px; display: flex; gap: 18px; flex-wrap: wrap; align-items: center; }}
  .meta span {{ display: inline-flex; align-items: center; gap: 7px; }}
  .meta .sep {{ color: var(--text-dim); }}
  .pulse {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 0 rgba(34,197,94,0.6); animation: pulse 2s infinite; }}
  @keyframes pulse {{
    0% {{ box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.55); }}
    70% {{ box-shadow: 0 0 0 8px rgba(34, 197, 94, 0); }}
    100% {{ box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }}
  }}
  .actions {{ display: flex; gap: 10px; align-items: center; }}
  .btn {{
    display: inline-flex; align-items: center; gap: 8px;
    background: linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 100%);
    color: #fff; font-weight: 600; font-size: 13.5px; padding: 10px 18px; border-radius: 10px;
    text-decoration: none; border: none; cursor: pointer;
    box-shadow: 0 6px 20px -4px rgba(99, 102, 241, 0.5);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }}
  .btn:hover {{ transform: translateY(-1px); box-shadow: 0 8px 24px -4px rgba(99, 102, 241, 0.65); }}
  .btn-ghost {{ background: var(--bg-elev); color: var(--text); border: 1px solid var(--border); box-shadow: none; }}
  .btn-ghost:hover {{ background: var(--bg-elev-2); transform: none; box-shadow: none; border-color: var(--border-strong); }}

  /* Overview */
  .overview {{ display: grid; grid-template-columns: 340px 1fr; gap: 20px; margin-bottom: 22px; }}
  @media (max-width: 900px) {{ .overview {{ grid-template-columns: 1fr; }} }}
  .health-card {{
    background: linear-gradient(180deg, var(--bg-elev) 0%, var(--bg-elev-2) 100%);
    border: 1px solid var(--border); border-radius: 18px; padding: 26px;
    display: flex; flex-direction: column; align-items: center; gap: 18px;
  }}
  .health-ring {{ position: relative; width: 188px; height: 188px; }}
  .health-ring svg {{ transform: rotate(-90deg); display: block; }}
  .health-ring .pct {{ position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }}
  .health-ring .pct .big {{ font-size: 42px; font-weight: 800; letter-spacing: -0.03em; line-height: 1; }}
  .health-ring .pct .lbl {{ font-size: 10.5px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.12em; margin-top: 6px; font-weight: 600; }}
  .summary-text {{ font-size: 13.5px; color: var(--text-muted); text-align: center; line-height: 1.6; }}
  .summary-text strong {{ color: var(--text); font-weight: 700; }}

  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; align-content: start; }}
  .stat {{
    background: var(--bg-elev); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px;
    transition: border-color 0.15s ease, transform 0.15s ease;
    position: relative; overflow: hidden;
  }}
  .stat:hover {{ border-color: var(--border-strong); transform: translateY(-1px); }}
  .stat .num {{ font-size: 30px; font-weight: 800; line-height: 1; margin-bottom: 6px; letter-spacing: -0.025em; font-variant-numeric: tabular-nums; }}
  .stat .lbl {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; display: flex; align-items: center; gap: 7px; }}
  .stat .lbl::before {{ content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: 0.85; }}
  .stat.s-ok {{ background: linear-gradient(135deg, var(--green-soft), transparent 80%); }}
  .stat.s-ok .num, .stat.s-ok .lbl {{ color: var(--green); }}
  .stat.s-down, .stat.s-sslbad {{ background: linear-gradient(135deg, var(--red-soft), transparent 80%); }}
  .stat.s-down .num, .stat.s-down .lbl, .stat.s-sslbad .num, .stat.s-sslbad .lbl {{ color: var(--red); }}
  .stat.s-wrong {{ background: linear-gradient(135deg, var(--purple-soft), transparent 80%); }}
  .stat.s-wrong .num, .stat.s-wrong .lbl {{ color: var(--purple); }}
  .stat.s-act {{ background: linear-gradient(135deg, var(--blue-soft), transparent 80%); }}
  .stat.s-act .num, .stat.s-act .lbl {{ color: var(--blue); }}
  .stat.s-risk, .stat.s-warn {{ background: linear-gradient(135deg, var(--amber-soft), transparent 80%); }}
  .stat.s-risk .num, .stat.s-risk .lbl, .stat.s-warn .num, .stat.s-warn .lbl {{ color: var(--amber); }}

  /* Toolbar */
  .toolbar {{
    background: var(--bg-elev); border: 1px solid var(--border); border-radius: 14px;
    padding: 12px 14px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 14px;
  }}
  .search {{ flex: 1; min-width: 220px; position: relative; display: flex; align-items: center; }}
  .search input {{
    width: 100%; background: var(--bg); border: 1px solid var(--border); color: var(--text);
    border-radius: 10px; padding: 10px 14px 10px 38px; font-size: 13.5px; outline: none;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
    font-family: inherit;
  }}
  .search input::placeholder {{ color: var(--text-dim); }}
  .search input:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(99,102,241,0.18); }}
  .search svg {{ position: absolute; left: 12px; width: 16px; height: 16px; color: var(--text-dim); pointer-events: none; }}
  .filters {{ display: flex; gap: 6px; flex-wrap: wrap; }}
  .chip {{
    padding: 7px 13px; border-radius: 999px; font-size: 12px; font-weight: 600;
    border: 1px solid var(--border); background: var(--bg); color: var(--text-muted);
    cursor: pointer; transition: all 0.15s ease; user-select: none;
    display: inline-flex; align-items: center; gap: 6px;
  }}
  .chip:hover {{ color: var(--text); border-color: var(--border-strong); }}
  .chip.active {{ background: var(--text); color: var(--bg); border-color: var(--text); }}
  .chip .count {{ font-size: 10.5px; padding: 1px 6px; background: rgba(255,255,255,0.08); border-radius: 999px; }}
  .chip.active .count {{ background: rgba(0,0,0,0.18); }}
  .visible-count {{ margin-left: auto; color: var(--text-dim); font-size: 12px; font-variant-numeric: tabular-nums; }}

  /* Table */
  .table-wrap {{ background: var(--bg-elev); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  th, td {{ text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--text-muted); font-weight: 600; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.06em; background: var(--bg-elev-2); user-select: none; white-space: nowrap; }}
  th.sortable {{ cursor: pointer; }}
  th.sortable:hover {{ color: var(--text); }}
  th.sortable::after {{ content: ' ⇅'; opacity: 0.35; font-size: 10px; }}
  th.sort-asc::after {{ content: ' ↑'; opacity: 1; color: var(--accent); }}
  th.sort-desc::after {{ content: ' ↓'; opacity: 1; color: var(--accent); }}
  tbody tr {{ transition: background 0.1s ease; }}
  tbody tr:hover {{ background: rgba(255,255,255,0.025); }}
  tbody tr:last-child td {{ border-bottom: none; }}
  td.domain {{ font-weight: 500; }}
  td.domain a {{ color: var(--text); text-decoration: none; }}
  td.domain a:hover {{ color: var(--accent); }}
  td.dim, .muted, .dim {{ color: var(--text-muted); }}
  td.detail {{ color: var(--text-muted); max-width: 260px; }}
  .mono {{ font-family: 'JetBrains Mono', ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; }}

  /* Badges */
  .badge {{
    display: inline-flex; align-items: center; gap: 6px;
    font-weight: 700; font-size: 10.5px; letter-spacing: 0.04em;
    padding: 4px 10px; border-radius: 999px; text-transform: uppercase; white-space: nowrap;
  }}
  .badge::before {{ content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }}
  .b-ok {{ color: var(--green); background: var(--green-soft); }}
  .b-down, .b-sslbad {{ color: var(--red); background: var(--red-soft); }}
  .b-wrong {{ color: var(--purple); background: var(--purple-soft); }}
  .b-act {{ color: var(--blue); background: var(--blue-soft); }}
  .b-risk, .b-warn, .b-degraded {{ color: var(--amber); background: var(--amber-soft); }}

  .served-yes {{ color: var(--green); font-weight: 600; }}
  .served-no {{ color: var(--amber); font-weight: 600; }}

  /* SSL bar */
  .ssl-pill {{ display: inline-flex; align-items: center; gap: 10px; font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .ssl-bar {{ width: 56px; height: 5px; background: var(--border); border-radius: 999px; overflow: hidden; }}
  .ssl-bar > span {{ display: block; height: 100%; border-radius: 999px; }}
  .ssl-days {{ font-size: 12.5px; color: var(--text-muted); }}

  /* Response */
  .resp {{ font-variant-numeric: tabular-nums; font-weight: 500; }}
  .resp-fast {{ color: var(--green); }}
  .resp-mid {{ color: var(--amber); }}
  .resp-slow {{ color: var(--red); }}

  /* Footer */
  .legend {{
    margin-top: 20px; padding: 18px 20px; background: var(--bg-elev); border: 1px solid var(--border); border-radius: 14px;
    color: var(--text-muted); font-size: 12.5px; line-height: 1.7;
  }}
  .legend b {{ color: var(--text); font-weight: 700; }}
  .legend .legend-title {{ color: var(--text); font-weight: 700; font-size: 13px; margin-bottom: 8px; display: block; }}
  .legend ul {{ margin: 0; padding-left: 18px; }}
  .legend li {{ margin-bottom: 4px; }}

  .empty {{ padding: 56px 20px; text-align: center; color: var(--text-muted); display: none; }}
  .empty.show {{ display: block; }}

  ::selection {{ background: rgba(99,102,241,0.35); color: #fff; }}
</style></head>
<body><div class="wrap">

  <header class="header">
    <div class="title-block">
      <h1>Domain Monitor</h1>
      <div class="meta">
        <span><span class="pulse"></span> Live</span>
        <span class="sep">·</span>
        <span>Last check <span class="mono">{checked_at}</span></span>
        <span class="sep">·</span>
        <span><strong style="color:var(--text);">{total}</strong> domains</span>
        <span class="sep">·</span>
        <span><strong style="color:var(--text);">{workers}</strong> on Worker</span>
        <span class="sep">·</span>
        <span>SSL warn {ssl_warn}d</span>
        <span class="sep">·</span>
        <span>auto every 6h</span>
      </div>
    </div>
    <div class="actions">
      <a class="btn btn-ghost" href="https://github.com/growthack88/domain-monitor" target="_blank" rel="noopener">⌥ Repo</a>
      <a class="btn" href="{actions_url}" target="_blank" rel="noopener">↻ Check now</a>
    </div>
  </header>

  <section class="overview">
    <div class="health-card">
      <div class="health-ring">
        <svg viewBox="0 0 100 100" width="188" height="188">
          <defs>
            <linearGradient id="ring-grad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stop-color="{ring_start}"/>
              <stop offset="100%" stop-color="{ring_end}"/>
            </linearGradient>
          </defs>
          <circle cx="50" cy="50" r="42" fill="none" stroke="var(--border)" stroke-width="8"/>
          <circle cx="50" cy="50" r="42" fill="none" stroke="url(#ring-grad)" stroke-width="8"
            stroke-linecap="round" stroke-dasharray="{ring_visible} {ring_remainder}"/>
        </svg>
        <div class="pct">
          <div class="big" style="color:{ring_end};">{pct}%</div>
          <div class="lbl">Healthy</div>
        </div>
      </div>
      <div class="summary-text"><strong>{ok}</strong> of <strong>{total}</strong> domains operational<br>{issues_text}</div>
    </div>

    <div class="stats">{stat_cards}</div>
  </section>

  <div class="toolbar">
    <div class="search">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7" stroke-width="2"/><path d="M21 21l-4.3-4.3" stroke-width="2" stroke-linecap="round"/></svg>
      <input id="searchInput" placeholder="Search domain, project, host…" autocomplete="off" spellcheck="false"/>
    </div>
    <div class="filters" id="filterChips">
      <div class="chip active" data-filter="all">All <span class="count">{total}</span></div>
      <div class="chip" data-filter="issues">Issues <span class="count">{issues_count}</span></div>
      <div class="chip" data-filter="ok">OK <span class="count">{ok}</span></div>
      <div class="chip" data-filter="ssl">SSL <span class="count">{ssl_count}</span></div>
      <div class="chip" data-filter="worker">Worker <span class="count">{workers}</span></div>
    </div>
    <span class="visible-count" id="visibleCount"></span>
  </div>

  <div class="table-wrap">
    <table id="domainTable">
      <thead>
        <tr>
          <th></th>
          <th class="sortable" data-sort="domain">Domain</th>
          <th class="sortable" data-sort="status">Status</th>
          <th>Detail</th>
          <th>Served</th>
          <th>Project</th>
          <th class="sortable" data-sort="ssl">SSL</th>
          <th class="sortable" data-sort="resp">Response</th>
          <th>Host</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <div class="empty" id="emptyState">No domains match the current filter.</div>
  </div>

  <div class="legend">
    <span class="legend-title">Status legend</span>
    Worker-aware monitor using the Lovable proxy methodology.
    <ul>
      <li><b>AT RISK</b> — loads but not via the Worker (still on the old path; Lovable will disconnect it).</li>
      <li><b>NEEDS ACTION</b> — Worker loop-guard; remove the custom domain inside that Lovable project so its <span class="mono">*.lovable.app</span> stops redirecting.</li>
      <li><b>WRONG PROJECT</b> — served via Worker but content doesn't match the expected project (check <span class="mono">worker_map.json</span>).</li>
    </ul>
  </div>
</div>

<script>
  const rows = Array.from(document.querySelectorAll('#domainTable tbody tr'));
  const searchInput = document.getElementById('searchInput');
  const chips = document.querySelectorAll('#filterChips .chip');
  const emptyState = document.getElementById('emptyState');
  const visibleCount = document.getElementById('visibleCount');
  let currentFilter = 'all';

  function applyFilters() {{
    const q = searchInput.value.trim().toLowerCase();
    let visible = 0;
    rows.forEach(tr => {{
      const hay = (tr.dataset.domain + ' ' + (tr.dataset.project || '') + ' ' + (tr.dataset.host || '')).toLowerCase();
      const matchesSearch = !q || hay.includes(q);
      const status = tr.dataset.status;
      const onWorker = tr.dataset.worker === '1';
      let matchesFilter = true;
      if (currentFilter === 'issues') matchesFilter = status !== 'OK';
      else if (currentFilter === 'ok') matchesFilter = status === 'OK';
      else if (currentFilter === 'ssl') matchesFilter = status === 'SSL_INVALID' || status === 'SSL_EXPIRING';
      else if (currentFilter === 'worker') matchesFilter = onWorker;
      const show = matchesSearch && matchesFilter;
      tr.style.display = show ? '' : 'none';
      if (show) visible++;
    }});
    emptyState.classList.toggle('show', visible === 0);
    visibleCount.textContent = visible + ' shown';
  }}

  searchInput.addEventListener('input', applyFilters);
  chips.forEach(c => c.addEventListener('click', () => {{
    chips.forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    currentFilter = c.dataset.filter;
    applyFilters();
  }}));

  // Sortable columns
  const ths = document.querySelectorAll('th.sortable');
  const tbody = document.querySelector('#domainTable tbody');
  ths.forEach(th => th.addEventListener('click', () => {{
    const key = th.dataset.sort;
    const asc = !th.classList.contains('sort-asc');
    ths.forEach(x => x.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(asc ? 'sort-asc' : 'sort-desc');
    const sorted = rows.slice().sort((a, b) => {{
      const va = a.dataset[key], vb = b.dataset[key];
      const na = parseFloat(va), nb = parseFloat(vb);
      if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
      return asc ? String(va).localeCompare(vb) : String(vb).localeCompare(va);
    }});
    sorted.forEach(tr => tbody.appendChild(tr));
  }}));

  // Keyboard shortcut: "/" focuses search
  document.addEventListener('keydown', (e) => {{
    if (e.key === '/' && document.activeElement !== searchInput) {{
      e.preventDefault();
      searchInput.focus();
    }}
  }});

  applyFilters();
</script>
</body></html>"""


def _build_row(r):
    sev = r["overall"]
    badge_class = SEV_BADGE_CLASS.get(sev, "b-ok")
    dot_color = SEV_COLOR.get(sev, "#888")
    detail = r.get("reason") or r["http"].get("error") or r["http"].get("code")
    detail = "—" if detail is None else str(detail)

    if r["ssl"]["ok"]:
        days = r["ssl"]["days_left"]
        expires = r["ssl"]["expires"]
        if days <= SSL_WARN_DAYS:
            bar_color = "var(--red)"
        elif days <= 30:
            bar_color = "var(--amber)"
        else:
            bar_color = "var(--green)"
        bar_width = max(0, min(days, 90)) / 90 * 100
        ssl_html = (
            f'<div class="ssl-pill" title="Expires {expires}">'
            f'<div class="ssl-bar"><span style="width:{bar_width:.0f}%;background:{bar_color}"></span></div>'
            f'<span class="ssl-days">{days}d</span></div>'
        )
        ssl_sort = days
    else:
        err = r["ssl"]["error"] or "invalid"
        ssl_html = f'<span style="color:var(--red);font-weight:600;">{err}</span>'
        ssl_sort = -1

    tms = r["http"]["time_ms"]
    if tms is None:
        resp_html = '<span class="dim">—</span>'
        resp_sort = 99999
    else:
        if tms < 500:
            cls = "resp-fast"
        elif tms < 1500:
            cls = "resp-mid"
        else:
            cls = "resp-slow"
        resp_html = f'<span class="resp {cls}">{tms} ms</span>'
        resp_sort = tms

    if r["via_worker"]:
        served = '<span class="served-yes">✓ Worker</span>'
    elif r["on_worker"]:
        served = '<span class="served-no">⚠ not Worker</span>'
    else:
        served = '<span class="dim">—</span>'

    project_name = r["worker_sub"] if r["on_worker"] else ""
    project_html = f'<span class="dim mono">{project_name}</span>' if project_name else '<span class="dim">—</span>'

    # status sort: severity rank (lower number = worse, shows first when ascending)
    status_sort = SEV_ORDER.get(sev, 9)

    return (
        f'\n      <tr data-domain="{r["domain"].lower()}" data-status="{sev}" '
        f'data-worker="{1 if r["on_worker"] else 0}" data-project="{project_name.lower()}" '
        f'data-host="{r["host"].lower()}" data-ssl="{ssl_sort}" data-resp="{resp_sort}">'
        f'\n        <td><span class="dot" style="background:{dot_color}"></span></td>'
        f'\n        <td class="domain"><a href="https://{r["domain"]}" target="_blank" rel="noopener">{r["domain"]}</a></td>'
        f'\n        <td data-status-sort="{status_sort}"><span class="badge {badge_class}">{SEV_LABEL.get(sev, sev)}</span></td>'
        f'\n        <td class="detail">{detail}</td>'
        f'\n        <td>{served}</td>'
        f'\n        <td>{project_html}</td>'
        f'\n        <td>{ssl_html}</td>'
        f'\n        <td>{resp_html}</td>'
        f'\n        <td class="dim">{r["host"]}</td>'
        f'\n      </tr>'
    )


def write_dashboard(results, checked_at):
    os.makedirs(DOCS_DIR, exist_ok=True)
    actions_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                   f"{os.environ.get('GITHUB_REPOSITORY', 'growthack88/domain-monitor')}"
                   f"/actions/workflows/monitor.yml")
    results = sorted(results, key=lambda r: (SEV_ORDER.get(r["overall"], 9), r["domain"]))
    counts = {}
    for r in results:
        counts[r["overall"]] = counts.get(r["overall"], 0) + 1

    total = len(results)
    ok_count = counts.get("OK", 0)
    issues_count = total - ok_count
    pct = round((ok_count / total) * 100) if total else 0
    workers_count = sum(1 for r in results if r["on_worker"])
    ssl_count = counts.get("SSL_INVALID", 0) + counts.get("SSL_EXPIRING", 0)

    # Donut gradient color depends on health
    if pct >= 95:
        ring_start, ring_end = "#22c55e", "#34d399"
    elif pct >= 80:
        ring_start, ring_end = "#f59e0b", "#fbbf24"
    else:
        ring_start, ring_end = "#ef4444", "#f87171"

    circ = 263.89  # 2 * pi * 42
    ring_visible = round(circ * pct / 100, 2)
    ring_remainder = round(circ - ring_visible, 2)

    if issues_count == 0:
        issues_text = "All systems operational"
    else:
        word = "issue" if issues_count == 1 else "issues"
        issues_text = f"<strong style='color:var(--amber);'>{issues_count}</strong> {word} need attention"

    # Stat cards — show all problem buckets even if 0; OK always shown
    stat_specs = [
        ("OK", "OK", "s-ok", True),
        ("DOWN", "Down", "s-down", False),
        ("WRONG_PROJECT", "Wrong project", "s-wrong", False),
        ("NEEDS_ACTION", "Needs action", "s-act", False),
        ("AT_RISK", "At risk", "s-risk", False),
        ("SSL_INVALID", "SSL invalid", "s-sslbad", False),
        ("SSL_EXPIRING", "SSL expiring", "s-warn", False),
        ("DEGRADED", "Degraded", "s-warn", False),
    ]
    stat_cards_parts = []
    for key, label, cls, always in stat_specs:
        n = counts.get(key, 0)
        if not always and n == 0:
            continue
        stat_cards_parts.append(
            f'<div class="stat {cls}"><div class="num">{n}</div><div class="lbl">{label}</div></div>'
        )
    stat_cards = "".join(stat_cards_parts)

    rows_html = "".join(_build_row(r) for r in results)

    html = DASHBOARD_TEMPLATE.format(
        checked_at=checked_at,
        total=total,
        ok=ok_count,
        issues_count=issues_count,
        pct=pct,
        workers=workers_count,
        ssl_warn=SSL_WARN_DAYS,
        ssl_count=ssl_count,
        actions_url=actions_url,
        stat_cards=stat_cards,
        rows=rows_html,
        issues_text=issues_text,
        ring_start=ring_start,
        ring_end=ring_end,
        ring_visible=ring_visible,
        ring_remainder=ring_remainder,
    )

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        json.dump({"checked_at": checked_at, "counts": counts, "results": results}, f, indent=2)


# ----------------------------- main -----------------------------
def main():
    domains = load_domains()
    print(f"Checking {len(domains)} domains... ({len(WORKER_MAP)} mapped to the Worker)")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(evaluate, domains))

    checked_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    prev = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                prev = json.load(f)
        except Exception:  # noqa: BLE001
            prev = {}

    new_problems, recovered = [], []
    cur_state = {}
    for r in results:
        sig = state_signature(r)
        cur_state[r["domain"]] = sig
        before = prev.get(r["domain"], "OK")
        now_bad = r["overall"] != "OK"
        if now_bad and sig != before:
            new_problems.append(r)
        elif before not in ("OK",) and not now_bad:
            recovered.append(r)

    write_dashboard(results, checked_at)

    problems = [r for r in results if r["overall"] != "OK"]
    print(f"Done. {len(problems)} issue(s):")
    for r in sorted(problems, key=lambda r: SEV_ORDER.get(r["overall"], 9)):
        print("  " + problem_line(r))

    send_alerts(new_problems, recovered)
    if new_problems or recovered:
        print(f"Slack: {len(new_problems)} new, {len(recovered)} recovered.")
    else:
        print("Slack: no state changes — nothing sent.")

    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        send_status_summary(results, checked_at)
        print("Manual run: full status summary posted.")
    elif prev.get("_pushover_last_date") != today:
        send_pushover_daily_digest(results, checked_at)
        print("Pushover: daily digest sent.")
    else:
        print("Pushover: already sent today — quiet.")

    cur_state["_pushover_last_date"] = today
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(cur_state, f, indent=2)


if __name__ == "__main__":
    main()
