#!/usr/bin/env python3
"""
Domain uptime + SSL monitor.

For every domain in domains.txt it checks:
  1. HTTP(S) reachability + the actual page (catches "domain not connected" error
     pages that still return a 2xx/421 status, e.g. Lovable / Vercel).
  2. TLS certificate -> valid?  days until expiry?

Alerting model:
  - SLACK: live. Posts on every run when a domain CHANGES state.
  - PUSHOVER: quiet. One digest per day, plus an instant reply on a manual check.
"""

import os
import ssl
import json
import socket
import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import requests

# ----------------------------- config -----------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
DOMAINS_FILE = os.path.join(ROOT, "domains.txt")
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

# Identify as a real browser so Cloudflare/WAFs don't bot-block the check.
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
}


# ----------------------------- checks -----------------------------
def load_domains():
    domains = []
    with open(DOMAINS_FILE, encoding="utf-8") as f:
        for line in f:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            d = d.replace("https://", "").replace("http://", "").strip("/")
            d = d.split("/")[0].split(",")[0].strip()
            if d:
                domains.append(d)
    seen, out = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def check_ssl(host, port=443):
    """Return dict with cert validity and days_left, or an error."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
        days_left = (expires - dt.datetime.now(dt.timezone.utc)).days
        return {
            "ok": True,
            "days_left": days_left,
            "expires": expires.strftime("%Y-%m-%d"),
            "error": None,
        }
    except ssl.SSLCertVerificationError as e:
        msg = getattr(e, "verify_message", None) or str(e)
        return {"ok": False, "days_left": None, "expires": None, "error": f"invalid cert: {msg}"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "days_left": None, "expires": None, "error": "TLS timeout"}
    except (socket.gaierror,):
        return {"ok": False, "days_left": None, "expires": None, "error": "DNS resolution failed"}
    except ConnectionRefusedError:
        return {"ok": False, "days_left": None, "expires": None, "error": "connection refused (no 443)"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "days_left": None, "expires": None, "error": f"TLS error: {e}"}


# Error pages that return a "success-ish" status but really mean the domain is
# NOT connected to a live project. (substring in page body -> human reason)
BROKEN_PAGE_SIGNATURES = [
    ("are not properly configured", "Lovable: domain/DNS not connected"),
    ("project not found", "Lovable: project not found"),
    ("deployment_not_found", "Vercel: deployment not found"),
    ("the deployment could not be found", "Vercel: deployment not found"),
    ("there isn't a github pages site here", "GitHub Pages: no site here"),
    ("site not found · netlify", "Netlify: site not found"),
    ("sorry, this shop is currently unavailable", "Shopify: shop unavailable"),
    ("no such app", "Host: no such app"),
]


def detect_broken_page(body_lower):
    for sig, reason in BROKEN_PAGE_SIGNATURES:
        if sig in body_lower:
            return reason
    return None


def check_http(domain):
    url = f"https://{domain}"
    try:
        r = requests.get(
            url, timeout=HTTP_TIMEOUT, allow_redirects=True,
            headers=BROWSER_HEADERS,
        )
        code = r.status_code
        try:
            body_lower = (r.text or "")[:6000].lower()
        except Exception:  # noqa: BLE001
            body_lower = ""
        broken = detect_broken_page(body_lower)

        err = None
        if broken:
            status, err = "DOWN", broken            # error page (e.g. unconnected Lovable domain)
        elif code == 421:
            status, err = "DOWN", "HTTP 421 — domain not connected to a project"
        elif code < 400:
            status = "UP"
        elif code in (401, 403, 429):
            status = "UP"         # server alive, just bot-gated (Cloudflare/WAF)
        elif code < 500:
            status = "DEGRADED"   # e.g. 404/410 — page issue but server responding
        else:
            status = "DOWN"       # 5xx (incl. Cloudflare 5xx like 521/526)
        return {
            "status": status,
            "code": code,
            "final_url": r.url,
            "server": r.headers.get("Server", ""),
            "time_ms": int(r.elapsed.total_seconds() * 1000),
            "error": err,
        }
    except requests.exceptions.SSLError as e:
        return {"status": "DOWN", "code": None, "final_url": url, "server": "",
                "time_ms": None, "error": f"TLS handshake failed: {str(e)[:160]}"}
    except requests.exceptions.ConnectTimeout:
        return {"status": "DOWN", "code": None, "final_url": url, "server": "",
                "time_ms": None, "error": "connect timeout"}
    except requests.exceptions.ReadTimeout:
        return {"status": "DOWN", "code": None, "final_url": url, "server": "",
                "time_ms": None, "error": "read timeout"}
    except requests.exceptions.ConnectionError as e:
        return {"status": "DOWN", "code": None, "final_url": url, "server": "",
                "time_ms": None, "error": f"connection error: {str(e)[:160]}"}
    except Exception as e:  # noqa: BLE001
        return {"status": "DOWN", "code": None, "final_url": url, "server": "",
                "time_ms": None, "error": str(e)[:160]}


def guess_host(server, final_url):
    s = (server or "").lower()
    u = (final_url or "").lower()
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

    down = http["status"] == "DOWN"
    ssl_invalid = not sslr["ok"]
    ssl_expiring = sslr["ok"] and sslr["days_left"] is not None and sslr["days_left"] <= SSL_WARN_DAYS

    if down:
        overall = "DOWN"
    elif ssl_invalid:
        overall = "SSL_INVALID"
    elif ssl_expiring:
        overall = "SSL_EXPIRING"
    elif http["status"] == "DEGRADED":
        overall = "DEGRADED"
    else:
        overall = "OK"

    return {
        "domain": domain,
        "overall": overall,
        "down": down,
        "ssl_invalid": ssl_invalid,
        "ssl_expiring": ssl_expiring,
        "http": http,
        "ssl": sslr,
        "host": guess_host(http.get("server"), http.get("final_url")),
    }


# ----------------------------- alerting -----------------------------
SEV_ORDER = {"DOWN": 0, "SSL_INVALID": 1, "SSL_EXPIRING": 2, "DEGRADED": 3, "OK": 4}


def state_signature(r):
    return f"{int(r['down'])}{int(r['ssl_invalid'])}{int(r['ssl_expiring'])}"


def problem_line(r):
    d = r["domain"]
    if r["down"]:
        err = r["http"]["error"] or f"HTTP {r['http']['code']}"
        return f"🔴 {d} — DOWN ({err})"
    if r["ssl_invalid"]:
        return f"🔒 {d} — SSL INVALID ({r['ssl']['error']})"
    if r["ssl_expiring"]:
        return f"⚠️ {d} — SSL expires in {r['ssl']['days_left']}d ({r['ssl']['expires']})"
    return f"✅ {d}"


def send_pushover(title, message, priority=1):
    if not (PUSHOVER_TOKEN and PUSHOVER_USER):
        return
    payload = {
        "token": PUSHOVER_TOKEN,
        "user": PUSHOVER_USER,
        "title": title[:250],
        "message": message[:1024],
        "priority": priority,
        "html": 1,
    }
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
    """Per-change alert. SLACK only (live). Pushover is a once-a-day digest."""
    if not new_problems and not recovered:
        return
    lines = []
    if new_problems:
        lines.append("*New issues:*")
        lines += [problem_line(r) for r in new_problems]
    if recovered:
        lines.append("")
        lines.append("*Recovered:*")
        lines += [f"✅ {r['domain']} back to normal" for r in recovered]
    body = "\n".join(lines)
    if DASHBOARD_URL:
        body += f"\n\nDashboard: {DASHBOARD_URL}"
    send_slack(body)


def send_pushover_daily_digest(results, checked_at):
    """One Pushover push per day summarising current problems (no per-run spam)."""
    problems = [r for r in results if r["overall"] != "OK"]
    if not problems:
        return
    lines = [f"{len(problems)} domain issue(s) — {checked_at}", ""]
    lines += [problem_line(r) for r in sorted(problems, key=lambda r: SEV_ORDER.get(r["overall"], 9))]
    send_pushover(f"🔴 {len(problems)} domain issue(s)", "\n".join(lines), priority=1)


def send_status_summary(results, checked_at):
    """Post the FULL current status (used for on-demand /sitecheck or 'Check now')."""
    counts = {k: 0 for k in SEV_ORDER}
    for r in results:
        counts[r["overall"]] = counts.get(r["overall"], 0) + 1
    problems = [r for r in results if r["overall"] != "OK"]
    header = (f"*Domain check — {checked_at}*\n"
              f"{counts.get('OK',0)} OK · {counts.get('DOWN',0)} down · "
              f"{counts.get('SSL_INVALID',0)} SSL invalid · "
              f"{counts.get('SSL_EXPIRING',0)} SSL expiring · "
              f"{counts.get('DEGRADED',0)} degraded")
    if problems:
        lines = [header, ""] + [
            problem_line(r) for r in sorted(problems, key=lambda r: SEV_ORDER.get(r["overall"], 9))
        ]
    else:
        lines = [header, "", "✅ All domains healthy."]
    body = "\n".join(lines)
    if DASHBOARD_URL:
        body += f"\n\nDashboard: {DASHBOARD_URL}"
    send_slack(body)
    send_pushover("Domain check", body.replace("*", ""), priority=0)


# ----------------------------- dashboard -----------------------------
SEV_COLOR = {
    "DOWN": "#e5484d", "SSL_INVALID": "#e5484d", "SSL_EXPIRING": "#f5a623",
    "DEGRADED": "#f5a623", "OK": "#30a46c",
}
SEV_LABEL = {
    "DOWN": "DOWN", "SSL_INVALID": "SSL INVALID", "SSL_EXPIRING": "SSL EXPIRING",
    "DEGRADED": "DEGRADED", "OK": "OK",
}


def write_dashboard(results, checked_at):
    os.makedirs(DOCS_DIR, exist_ok=True)
    actions_url = (
        f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
        f"{os.environ.get('GITHUB_REPOSITORY', 'growthack88/domain-monitor')}"
        f"/actions/workflows/monitor.yml"
    )
    results = sorted(results, key=lambda r: (SEV_ORDER.get(r["overall"], 9), r["domain"]))

    counts = {k: 0 for k in SEV_ORDER}
    for r in results:
        counts[r["overall"]] = counts.get(r["overall"], 0) + 1

    rows = []
    for r in results:
        color = SEV_COLOR.get(r["overall"], "#888")
        code = r["http"]["code"]
        # Prefer a human reason when something is wrong; otherwise show the code.
        code_txt = r["http"]["error"] or (code if code is not None else "—")
        if r["ssl"]["ok"]:
            ssl_txt = f"{r['ssl']['days_left']}d → {r['ssl']['expires']}"
        else:
            ssl_txt = r["ssl"]["error"] or "invalid"
        tms = r["http"]["time_ms"]
        tms_txt = f"{tms} ms" if tms is not None else "—"
        rows.append(f"""
      <tr>
        <td><span class="dot" style="background:{color}"></span></td>
        <td><a href="https://{r['domain']}" target="_blank" rel="noopener">{r['domain']}</a></td>
        <td><span class="badge" style="background:{color}">{SEV_LABEL.get(r['overall'], r['overall'])}</span></td>
        <td>{code_txt}</td>
        <td>{ssl_txt}</td>
        <td>{tms_txt}</td>
        <td class="muted">{r['host']}</td>
      </tr>""")

    summary = f"""
      <div class="card down">{counts.get('DOWN',0)}<span>Down</span></div>
      <div class="card sslbad">{counts.get('SSL_INVALID',0)}<span>SSL invalid</span></div>
      <div class="card warn">{counts.get('SSL_EXPIRING',0)}<span>SSL expiring</span></div>
      <div class="card deg">{counts.get('DEGRADED',0)}<span>Degraded</span></div>
      <div class="card ok">{counts.get('OK',0)}<span>OK</span></div>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Monitor</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin:0; background:#0f1115; color:#e6e8eb; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:28px 20px 60px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:#9aa0a6; font-size:13px; margin-bottom:22px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ flex:1; min-width:120px; background:#171a21; border:1px solid #232833;
          border-radius:12px; padding:16px; font-size:30px; font-weight:700; }}
  .card span {{ display:block; font-size:12px; font-weight:500; color:#9aa0a6; margin-top:4px; }}
  .card.down {{ color:#ff6b6f; }}
  .card.sslbad {{ color:#ff6b6f; }} .card.warn {{ color:#f5a623; }}
  .card.deg {{ color:#f5a623; }} .card.ok {{ color:#30a46c; }}
  table {{ width:100%; border-collapse:collapse; background:#171a21;
          border:1px solid #232833; border-radius:12px; overflow:hidden; }}
  th, td {{ text-align:left; padding:10px 12px; font-size:13px; border-bottom:1px solid #232833; }}
  th {{ color:#9aa0a6; font-weight:600; position:sticky; top:0; background:#13161c; }}
  tr:last-child td {{ border-bottom:none; }}
  a {{ color:#7cc0ff; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  .muted {{ color:#9aa0a6; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:50%; }}
  .badge {{ color:#0f1115; font-weight:700; font-size:11px; padding:2px 8px; border-radius:20px; }}
  .foot {{ margin-top:18px; color:#6b7280; font-size:12px; }}
  .btn {{ display:inline-block; margin:0 0 22px; background:#7cc0ff; color:#0f1115;
          font-weight:700; font-size:14px; padding:10px 18px; border-radius:8px; text-decoration:none; }}
  .btn:hover {{ filter:brightness(1.08); text-decoration:none; }}
  .btnhint {{ font-size:12px; color:#6b7280; margin-left:10px; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>Domain Monitor</h1>
    <div class="sub">{len(results)} domains · last checked {checked_at} · SSL warning threshold {SSL_WARN_DAYS} days · auto-checks every 6h</div>
    <a class="btn" href="{actions_url}" target="_blank" rel="noopener">🔄 Check now</a>
    <span class="btnhint">opens GitHub → click the green “Run workflow” button (takes ~30s, then reload this page)</span>
    <div class="cards">{summary}</div>
    <table>
      <thead><tr><th></th><th>Domain</th><th>Status</th><th>HTTP / detail</th><th>SSL (days → expiry)</th><th>Response</th><th>Host</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    <div class="foot">Generated automatically by GitHub Actions. "Domain not connected" pages (Lovable/Vercel) are flagged DOWN even when they return a 2xx/421 status.</div>
  </div>
</body>
</html>"""

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        json.dump({"checked_at": checked_at, "counts": counts, "results": results}, f, indent=2)


# ----------------------------- main -----------------------------
def main():
    domains = load_domains()
    print(f"Checking {len(domains)} domains...")

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
        had_problem_before = prev.get(r["domain"], "000") != "000"
        has_problem_now = sig != "000"
        if has_problem_now and sig != prev.get(r["domain"]):
            new_problems.append(r)
        elif had_problem_before and not has_problem_now:
            recovered.append(r)

    write_dashboard(results, checked_at)

    problems = [r for r in results if r["overall"] != "OK"]
    print(f"Done. {len(problems)} issue(s):")
    for r in sorted(problems, key=lambda r: SEV_ORDER.get(r["overall"], 9)):
        print("  " + problem_line(r))

    # Slack: per-change, live on every run
    send_alerts(new_problems, recovered)
    if new_problems or recovered:
        print(f"Slack: {len(new_problems)} new, {len(recovered)} recovered.")
    else:
        print("Slack: no state changes — nothing sent.")

    # Pushover: at most ONCE per day; manual runs answer immediately.
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        send_status_summary(results, checked_at)
        print("Manual run: full status summary posted to Slack + Pushover.")
    elif prev.get("_pushover_last_date") != today:
        send_pushover_daily_digest(results, checked_at)
        print("Pushover: daily digest sent (first scheduled run of the day).")
    else:
        print("Pushover: already sent today — staying quiet.")

    cur_state["_pushover_last_date"] = today
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(cur_state, f, indent=2)


if __name__ == "__main__":
    main()
