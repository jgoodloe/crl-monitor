# CRL Monitor (single-container edition)

A lightweight tool for monitoring X.509 **Certificate Revocation Lists (CRLs)**.
It periodically downloads the CRL for each certificate you configure, verifies
the CRL's signature against the issuer, checks its `thisUpdate` / `nextUpdate`
freshness window, looks up the certificate's serial in the revoked list, records
the result (valid / revoked / error), tracks download time, keeps a history of
status changes, and can push results to Uptime Kuma.

It is a sibling of [ocsp-monitor](https://github.com/jgoodloe/ocsp-monitor) and
follows the same single-container concept, but checks **CRLs** instead of OCSP
responders. The CRL verification logic is adapted from
[OCSPTesting](https://github.com/jgoodloe/OCSPTesting), reimplemented in-process
with the `cryptography` library (no `openssl` CLI / `subprocess`).

The UI and API are served by the same Flask process on the same origin, and
every request the browser makes is **relative**, so the app works behind a
reverse proxy — including under a subpath — with no URL configuration.

## Why single-container

- **One upstream for your reverse proxy.** No CORS, no cross-service routing, no
  separate API port to expose.
- **No external database.** State lives in SQLite on a Docker volume. Fine for
  the intended scale of **fewer than ~30 monitors**.
- **Built-in scheduler.** A background thread runs due checks; no cron, no job
  queue, no worker container.

## Quick start

```bash
git clone https://github.com/jgoodloe/crl-monitor.git
cd crl-monitor
cp .env.example .env        # optional; defaults are sensible
docker compose up -d --build
```

Open <http://localhost:8080>. Click **+ Add monitor** and provide:

- **Alias** — a name for the dashboard.
- **Certificate to check (PEM)** — the cert whose revocation status you want.
- **Issuer certificate (PEM)** — the CA cert that issued it (required to verify
  the CRL signature and match the CRL issuer).
- **CRL URL** — optional. If left blank, the app uses the CRL distribution point
  embedded in the certificate's `CRLDistributionPoints` extension.
- **Frequency**, **Uptime Kuma URL**, **Enabled** — as needed.

The first check runs immediately; subsequent checks run on the schedule. Use
**Check** on any row to run an on-demand check, or **Clone** to open the form
pre-filled from an existing monitor as a new copy (handy for monitoring several
certs from the same CA / CRL).

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port the app listens on inside the container. |
| `URL_PREFIX` | *(empty)* | Subpath to mount under, e.g. `/crl`. Leave empty for root or a dedicated (sub)domain. |
| `SCHEDULER_INTERVAL` | `30` | How often (seconds) the scheduler looks for due checks. |
| `CRL_TIMEOUT` | `30` | Per-request CRL HTTP timeout (seconds). |
| `MAX_CRL_BYTES` | `16777216` | Default maximum CRL download size (bytes). Larger CRLs are rejected. Overridable at runtime in **Settings** (e.g. raise it for large US-government CRLs). |
| `HISTORY_LIMIT` | `200` | Status-history rows retained per monitor. |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR`. |
| `DATA_DIR` | `/data` | Where the SQLite DB is stored (mount a volume here). |
| `TRUSTED_PROXY_HOPS` | `1` | Proxy hops to trust for `X-Forwarded-*`. Set `0` to disable `ProxyFix` when exposed directly. |
| `CRL_BLOCK_PRIVATE` | `true` | Block RFC 1918 / unique-local destinations for CRL and Kuma fetches. |
| `CRL_ALLOWED_HOSTS` | *(empty)* | Comma-separated hostnames / IPs / CIDRs that bypass the private-range block. |
| `MAX_PEM_BYTES` | `32768` | Maximum accepted size per PEM field. |
| `MAX_MONITORS` | `100` | Maximum monitors (0 = unlimited). |
| `RATE_LIMIT_MUTATE` | `60` | Per-IP create/update/delete/settings requests per minute (0 = off). |
| `RATE_LIMIT_CHECK` | `20` | Per-IP on-demand check requests per minute (0 = off). |

## Security

This app has **no built-in authentication** — run it behind a reverse proxy
that handles auth, and on a trusted network. The hardening below reduces the
blast radius but does not replace access control.

- **SSRF egress controls.** The CRL URL, the URLs from a certificate's
  `CRLDistributionPoints` extension, and the Uptime Kuma push URL are all
  validated before any server-side fetch: only `http`/`https` is allowed,
  redirects are disabled, and loopback / link-local (incl. the
  `169.254.169.254` cloud-metadata address) / multicast / reserved destinations
  are always blocked. Private (RFC 1918 / ULA) ranges are blocked too unless you
  set `CRL_BLOCK_PRIVATE=false` — internal-PKI users fetching CRLs from private
  hosts should instead allowlist them via `CRL_ALLOWED_HOSTS` (hostnames, IPs, or
  CIDRs). Connections are pinned to the validated IP to limit DNS rebinding.
- **Download cap.** CRL downloads are capped at the configured maximum size
  (streamed) so a hostile or oversized endpoint can't exhaust memory. The cap
  defaults to `MAX_CRL_BYTES` and can be adjusted at runtime in **Settings**.
- **CSRF.** State-changing API requests require an `X-Requested-With` header and
  a JSON content type, which browsers can't send cross-origin without a CORS
  preflight the app never grants.
- **Secrets.** The Uptime Kuma push URL embeds a token. It is stored in SQLite
  and never logged. The bulk list endpoint returns it **masked**, but the
  single-monitor detail view (used by the edit/clone form) returns it in full so
  the operator can verify it — keep the app behind your reverse proxy.
- **Error messages.** Network/parse errors are returned to clients as generic,
  category-level messages (full detail is logged server-side) so they can't be
  used as an SSRF reconnaissance oracle.
- **Abuse limits.** Per-IP rate limits on mutating and on-demand-check
  endpoints, a cap on PEM size, and a cap on monitor count.
- **Direct exposure.** `docker-compose.yml` binds to `127.0.0.1`. If you expose
  the container directly, set `TRUSTED_PROXY_HOPS=0` so clients can't spoof
  `X-Forwarded-*` headers.

## Reverse proxy

The app trusts `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and
`X-Forwarded-Prefix` (one proxy hop) via Werkzeug's `ProxyFix`.

### Own (sub)domain at root — simplest

Leave `URL_PREFIX` empty.

**nginx:**
```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Under a subpath, e.g. `https://host/crl`

Set `URL_PREFIX=/crl` (in `.env` or compose). The UI uses relative paths, so it
adapts automatically; setting the prefix makes the app respond at `/crl/...`
and correctly 404 elsewhere.

**nginx (no trailing slash on `proxy_pass`, so the `/crl` prefix is preserved):**
```nginx
location /crl/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /crl;
}
```

### Traefik (labels)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.crl.rule=Host(`crl.example.com`)"
  - "traefik.http.services.crl.loadbalancer.server.port=8080"
```

## How a check works

For each enabled monitor whose `next_run` is due, the app:

1. Loads the certificate and issuer from stored PEM.
2. Resolves a CRL distribution point — an explicit override URL, otherwise the
   URLs in the certificate's `CRLDistributionPoints` extension.
3. Downloads the CRL (streamed, size-capped, HTTP redirects disabled) and parses
   it as DER (falling back to PEM) with the `cryptography` library.
4. Verifies the CRL signature against the issuer, confirms the CRL issuer matches
   the issuer certificate, checks `thisUpdate` / `nextUpdate` freshness, and looks
   up the certificate's serial number in the revoked list.
5. Stores status, message, download time, and the update window; appends a
   history row **only when the status changes**; optionally pushes to Uptime
   Kuma.

No `openssl` CLI is invoked — it's all in-process via `cryptography`.

## Enabling / disabling a monitor

Each monitor can be enabled or disabled from its row (or the edit form). A
disabled monitor is skipped by the scheduler. Every enable/disable (and the
initial create) is written to an **audit log** with a timestamp, both for the
trail (`GET /api/monitors/{id}/audit`) and so uptime reports can account for the
periods a monitor was intentionally off.

## Uptime reports & maintenance windows

Open **Reports** in the toolbar. Pick a time frame (quick ranges or custom
from/to) and, optionally, specific monitors (none selected = all). Three views:

- **Uptime** — per-monitor uptime %, with a breakdown of up / down / maintenance
  / disabled / no-data time, and the list of downtimes in range. Each downtime
  shows the **reason** and an editable **comment** stored on the status-change
  event for future reports.
- **All downtimes** — a single chronological list of every downtime across the
  selected monitors for the period.
- **Maintenance windows** — define windows (per monitor or for all monitors)
  whose time is **excluded** from uptime calculations.

Uptime is **time-weighted**: each status holds from its change until the next,
and the percentage is up-time ÷ (up + down) over the window. Three options are
chosen *at report time*:

- **Down counts as** — *anything not Valid* (Revoked/Error count as down) or
  *only errors* (Revoked is treated as “answered” = up).
- **Disabled periods** — *excluded* from totals, *counted as downtime*, or
  *ignored* (use whatever status was last recorded).
- **Exclude maintenance** — whether maintenance-window time is removed from
  totals (downtimes inside a window are shown but flagged as excluded).

## Selectable verification tests

Every step of a check is an individually selectable **test**, in two groups.

**Foundational tests** form a dependency chain — each one is a prerequisite for
the next. When one fails the check can't continue, so the dependent tests are
skipped. They're all on by default; deselecting one means its failure is still
recorded but no longer flips the monitor to an error.

| Foundational test | What it checks |
|---|---|
| **Certificate & issuer load** | Both PEMs parse into valid X.509 certificates. |
| **CRL URL available** | A URL was supplied or found in the cert's CRL Distribution Points. |
| **CRL distribution point reachable** | The HTTP GET to a distribution point succeeds. |
| **HTTP 200 response** | A distribution point returns status code 200. |
| **CRL parses (DER/PEM)** | The body decodes as a DER (or PEM) X.509 CRL. |

**Evaluation tests** inspect a successfully parsed CRL:

| Evaluation test | What it checks |
|---|---|
| **Certificate revocation status** | The certificate's serial is **not** present in the CRL's revoked list. |
| **CRL signature verification** | The CRL is cryptographically signed by the issuer certificate. |
| **CRL issuer match** | The CRL's `issuer` matches the issuer certificate's subject. |
| **thisUpdate sanity** | `thisUpdate` (last update) is present and not future-dated (5 min skew). |
| **nextUpdate freshness** | `nextUpdate` is present and not already in the past (stale CRL). |
| **Response-time threshold** | The CRL download round-trip is under a configurable limit (ms). Off by default. |

Selection works at two levels:

- **Global default** (Settings → *Default verification tests*) applies to every
  monitor that doesn't override it. Stored in the `default_tests` setting. The
  default set is everything *except* **Response-time threshold**, which is opt-in.
- **Per monitor** (Add/Edit → *Verification tests*) either inherits the global
  default or pins its own set.

The dashboard shows a coloured pill per test on each monitor's row (green =
pass, red = fail, grey = skipped), and the overall status reflects only the
tests you enabled — e.g. disabling **Certificate revocation status** means a
revoked cert won't flip the monitor to `Revoked`.

> **Note:** This tool is aimed at PKIs where CRLs are published and required —
> e.g. federal PIV/PIV-I — and works against any HTTP(S)-published RFC 5280 CRL.

## API

All endpoints are under `<prefix>/api`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Health check (used by Docker HEALTHCHECK). |
| GET | `/api/monitors` | List monitors (no PEM payload). |
| POST | `/api/monitors` | Create a monitor. |
| GET | `/api/monitors/{id}` | Get one monitor (includes PEM). |
| PUT | `/api/monitors/{id}` | Update a monitor. |
| DELETE | `/api/monitors/{id}` | Delete a monitor. |
| POST | `/api/monitors/{id}/check` | Run a check now. |
| POST | `/api/monitors/{id}/enable` | Enable the monitor (audited). |
| POST | `/api/monitors/{id}/disable` | Disable the monitor (audited). |
| GET | `/api/monitors/{id}/history?limit=N` | Status-change history (with `id` + `comment`). |
| GET | `/api/monitors/{id}/audit` | Enable/disable/create audit log. |
| PUT | `/api/history/{id}` | Set/clear the comment on a status-change row. |
| GET/POST | `/api/maintenance` | List / create maintenance windows. |
| DELETE | `/api/maintenance/{id}` | Delete a maintenance window. |
| GET | `/api/reports/uptime` | Per-monitor uptime + downtimes for a window. |
| GET | `/api/reports/downtimes` | Flat downtime list across selected monitors. |
| GET | `/api/tests` | Catalogue of selectable verification tests (`key` + `label`). |
| GET/PUT | `/api/settings` | Logging settings and the global `default_tests`. |

The report endpoints accept `from`/`to` (ISO 8601), `monitor_ids` (CSV; empty
= all), `down_mode` (`not_valid`|`error_only`), `disabled_mode`
(`exclude`|`down`|`ignore`), and `exclude_maintenance` (`true`|`false`).

Monitor objects carry a `tests` field: `null` means "inherit the global default
set", and an array of test keys (e.g. `["cert_status","crl_signature"]`) pins
that monitor's own selection. A `response_time_ms` field (or `null` to inherit
the global default) sets the limit for the response-time test. The most recent
per-test outcomes are returned in `last_checks`. The `uptime_kuma_url` field is
returned in full by the single-monitor `GET /api/monitors/<id>` and **masked**
in the `GET /api/monitors` list; a boolean `uptime_kuma_url_set` indicates
whether one is configured.

State-changing requests (`POST`/`PUT`/`DELETE`) must include an
`X-Requested-With` header and a JSON body, and are rate-limited per client IP.

## Data & backup

Everything is in the `crl_data` volume at `/data/crl_monitor.db`. Back it up
with:

```bash
docker compose exec crl-monitor sh -c "cat /data/crl_monitor.db" > backup.db
```

## Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

`tests/test_crl.py` builds a throwaway CA, certificate and signed CRL in memory
and drives the check engine end to end (valid, revoked, bad signature, stale,
unreachable). `tests/test_security.py` guards the SSRF egress controls,
IP-pinned fetch, CSRF requirement, and XSS-safe rendering.

## Notes

- Run with a **single** gunicorn worker (the Dockerfile does this) so the
  in-process scheduler runs exactly once. Concurrency for the handful of
  monitors + UI comes from threads, which is plenty for I/O-bound CRL downloads.
- For more than a few dozen monitors — or very large CRLs — you'd want a real
  scheduler/queue and a client/server database; out of scope here by design.
