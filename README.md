# Domain Monitor

Automated uptime + SSL monitoring for 71 domains. Runs on GitHub Actions every 6 hours,
sends **Pushover** and **Slack** alerts when something breaks, and publishes a **live dashboard**
to GitHub Pages.

It specifically catches the failure that bit you before: **broken / expired SSL certificates**
(common with Lovable projects) — not just full outages.

## What it checks

For every domain:
- **HTTP status** → `UP` (2xx/3xx), `DEGRADED` (4xx, e.g. an auth wall — server is alive),
  or `DOWN` (5xx, timeout, DNS failure, connection refused, or TLS handshake failure).
- **TLS certificate** → valid? how many days until expiry? Flags invalid certs and certs
  expiring within 14 days (configurable).

Alerts fire **only on a state change** — newly down, SSL newly broken/expiring, or recovered.
No spam every 6 hours.

## One-time setup (≈5 minutes)

### 1. Add your alert credentials as repository secrets
**Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Where to get it |
|---|---|
| `PUSHOVER_TOKEN` | Pushover → Apps & Plugins → *Create an Application* → API Token |
| `PUSHOVER_USER` | Pushover dashboard → *Your User Key* |
| `SLACK_WEBHOOK_URL` | Slack → *Incoming Webhooks* → Add to a channel → copy the webhook URL |

> All three are optional. Add only the channels you want. If none are set, the monitor still
> runs and updates the dashboard — it just won't send alerts.

### 2. Enable the live dashboard (GitHub Pages)
**Settings → Pages → Source: Deploy from a branch → Branch: `main`, Folder: `/docs` → Save.**

> Free GitHub accounts serve Pages only from a **public** repo. To keep a live URL for free,
> make the repo public (nothing sensitive is stored here — alert tokens live in encrypted
> Secrets, not in the code). Or keep it private with GitHub Pro for private Pages.

Dashboard URL after the first run: `https://<your-username>.github.io/<repo-name>/`

### 3. (Optional) Put the dashboard link inside alerts
**Settings → Secrets and variables → Actions → Variables tab → New variable:**
`DASHBOARD_URL` = your Pages URL.

### 4. Allow the workflow to commit results
**Settings → Actions → General → Workflow permissions → Read and write permissions → Save.**

### 5. Run it once now
**Actions → Domain Monitor → Run workflow.** The first run seeds the baseline; later runs
compare against it and alert only on changes.

## Tuning

- **Add/remove domains:** edit `domains.txt` (one per line, `#` for comments).
- **Change frequency:** edit the `cron` in `.github/workflows/monitor.yml`
  (e.g. `0 */1 * * *` = hourly). Times are UTC.
- **SSL warning window:** change `SSL_WARN_DAYS` in the workflow (default `14`).

## Files
- `monitor.py` — the checker + dashboard/alert generator.
- `domains.txt` — your domain list.
- `.github/workflows/monitor.yml` — the 6-hourly schedule.
- `docs/` — auto-generated dashboard (`index.html`) + `status.json`.
- `state.json` — auto-managed; remembers last status so alerts only fire on change.

## Run locally (optional)
```bash
pip install -r requirements.txt
export PUSHOVER_TOKEN=... PUSHOVER_USER=... SLACK_WEBHOOK_URL=...
python monitor.py
open docs/index.html
```
