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
SEV_COLOR = {"DOWN": "#e5484d", "WRONG_PROJECT": "#a855f7", "SSL_INVALID": "#e5484d",
             "NEEDS_ACTION": "#3b82f6", "SSL_EXPIRING": "#f5a623", "AT_RISK": "#f59e0b",
             "DEGRADED": "#f5a623", "OK": "#30a46c"}
SEV_LABEL = {"DOWN": "DOWN", "WRONG_PROJECT": "WRONG PROJECT", "SSL_INVALID": "SSL INVALID",
             "NEEDS_ACTION": "NEEDS ACTION", "SSL_EXPIRING": "SSL EXPIRING",
             "AT_RISK": "AT RISK", "DEGRADED": "DEGRADED", "OK": "OK"}


def write_dashboard(results, checked_at):
    os.makedirs(DOCS_DIR, exist_ok=True)
    actions_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                   f"{os.environ.get('GITHUB_REPOSITORY', 'growthack88/domain-monitor')}"
                   f"/actions/workflows/monitor.yml")
    results = sorted(results, key=lambda r: (SEV_ORDER.get(r["overall"], 9), r["domain"]))
    counts = {}
    for r in results:
        counts[r["overall"]] = counts.get(r["overall"], 0) + 1

    rows = []
    for r in results:
        color = SEV_COLOR.get(r["overall"], "#888")
        detail = r.get("reason") or r["http"].get("error") or (r["http"].get("code") if r["http"].get("code") is not None else "—")
        ssl_txt = f"{r['ssl']['days_left']}d → {r['ssl']['expires']}" if r["ssl"]["ok"] else (r["ssl"]["error"] or "invalid")
        tms = r["http"]["time_ms"]
        tms_txt = f"{tms} ms" if tms is not None else "—"
        served = ("✓ Worker" if r["via_worker"] else ("⚠ not Worker" if r["on_worker"] else "—"))
        proj = f'<span class="muted">{r["worker_sub"]}</span>' if r["on_worker"] else "—"
        rows.append(f"""
      <tr>
        <td><span class="dot" style="background:{color}"></span></td>
        <td><a href="https://{r['domain']}" target="_blank" rel="noopener">{r['domain']}</a></td>
        <td><span class="badge" style="background:{color}">{SEV_LABEL.get(r['overall'], r['overall'])}</span></td>
        <td>{detail}</td>
        <td>{served}</td>
        <td>{proj}</td>
        <td>{ssl_txt}</td>
        <td>{tms_txt}</td>
        <td class="muted">{r['host']}</td>
      </tr>""")

    summary = f"""
      <div class="card down">{counts.get('DOWN',0)}<span>Down</span></div>
      <div class="card wrong">{counts.get('WRONG_PROJECT',0)}<span>Wrong project</span></div>
      <div class="card act">{counts.get('NEEDS_ACTION',0)}<span>Needs action</span></div>
      <div class="card risk">{counts.get('AT_RISK',0)}<span>At risk</span></div>
      <div class="card sslbad">{counts.get('SSL_INVALID',0)}<span>SSL invalid</span></div>
      <div class="card warn">{counts.get('SSL_EXPIRING',0)}<span>SSL expiring</span></div>
      <div class="card ok">{counts.get('OK',0)}<span>OK</span></div>
    """

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Monitor</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; margin:0; background:#0f1115; color:#e6e8eb; }}
  .wrap {{ max-width:1180px; margin:0 auto; padding:28px 20px 60px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:#9aa0a6; font-size:13px; margin-bottom:22px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ flex:1; min-width:104px; background:#171a21; border:1px solid #232833; border-radius:12px; padding:16px; font-size:28px; font-weight:700; }}
  .card span {{ display:block; font-size:12px; font-weight:500; color:#9aa0a6; margin-top:4px; }}
  .card.down,.card.sslbad {{ color:#ff6b6f; }} .card.wrong {{ color:#c084fc; }}
  .card.act {{ color:#60a5fa; }} .card.risk,.card.warn {{ color:#f5a623; }} .card.ok {{ color:#30a46c; }}
  table {{ width:100%; border-collapse:collapse; background:#171a21; border:1px solid #232833; border-radius:12px; overflow:hidden; }}
  th,td {{ text-align:left; padding:10px 12px; font-size:13px; border-bottom:1px solid #232833; }}
  th {{ color:#9aa0a6; font-weight:600; position:sticky; top:0; background:#13161c; }}
  tr:last-child td {{ border-bottom:none; }}
  a {{ color:#7cc0ff; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  .muted {{ color:#9aa0a6; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:50%; }}
  .badge {{ color:#0f1115; font-weight:700; font-size:11px; padding:2px 8px; border-radius:20px; }}
  .foot {{ margin-top:18px; color:#6b7280; font-size:12px; line-height:1.6; }}
  .btn {{ display:inline-block; margin:0 0 22px; background:#7cc0ff; color:#0f1115; font-weight:700; font-size:14px; padding:10px 18px; border-radius:8px; text-decoration:none; }}
</style></head>
<body><div class="wrap">
  <h1>Domain Monitor</h1>
  <div class="sub">{len(results)} domains · last checked {checked_at} · SSL warn {SSL_WARN_DAYS}d · {sum(1 for r in results if r['on_worker'])} on Cloudflare Worker · auto every 6h</div>
  <a class="btn" href="{actions_url}" target="_blank" rel="noopener">🔄 Check now</a>
  <div class="cards">{summary}</div>
  <table>
    <thead><tr><th></th><th>Domain</th><th>Status</th><th>Detail</th><th>Served</th><th>Project</th><th>SSL</th><th>Resp</th><th>Host</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <div class="foot">
    Worker-aware monitor (Lovable proxy methodology).
    <b>AT RISK</b> = loads but not via the Worker (still on the old path — Lovable will disconnect it).
    <b>NEEDS ACTION</b> = Worker loop-guard; remove the custom domain inside that Lovable project so its *.lovable.app stops redirecting.
    <b>WRONG PROJECT</b> = served via Worker but content doesn't match the expected project (check worker_map.json).
  </div>
</div></body></html>"""

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
