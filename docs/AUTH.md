# Authentication

CRL Monitor can require sign-in, via **OIDC single sign-on** (e.g. authentik) and
a **local username/password fallback**. It has no roles or per-object ownership:
**any authenticated user gets full access**. Access can optionally be narrowed to
members of specific IdP groups (see [Group restriction](#optional-group-restriction)).

## Default: fail closed

Authentication is **off by default**, but the app will **refuse to start** with no
auth configured — because that would let anyone who can reach the port use it with
full access. You must either configure auth (below) or explicitly opt into open
mode for an isolated/single-user box:

```ini
CRL_ALLOW_OPEN_MODE=true     # no login; only safe when nothing else can reach it
```

## Concepts

- **User** — either an **OIDC** identity (matched on the stable `sub` claim, never
  email, which can change or be reassigned) or a **local** account. Local passwords
  are hashed with **argon2id**.
- **Break-glass admin** — a local account created from the environment at startup.
  It is the fallback that keeps the app usable when the IdP is down, and it is how
  you get in before OIDC is wired.
- **Session** — the app issues its own signed, `HttpOnly` session cookie
  (`SameSite=Lax`, `Secure` on HTTPS). The browser never holds the IdP's tokens.
  Cookies are signed with `CRL_SESSION_SECRET`.

## Turning auth on

Set a session secret and a break-glass admin password and auth is enforced:

```ini
CRL_SESSION_SECRET=$(openssl rand -hex 32)     # signs session cookies
CRL_BOOTSTRAP_ADMIN_PASSWORD=change-me         # break-glass local admin
# CRL_BOOTSTRAP_ADMIN_USERNAME=admin           # optional, defaults to "admin"
```

At startup the break-glass admin (`CRL_BOOTSTRAP_ADMIN_USERNAME`, default `admin`)
is created, or its password refreshed from the env, so you can always recover
access. Sign in with it at the login screen.

> Set `CRL_SESSION_SECRET` to a **stable** value in production. Without it an
> ephemeral key is generated and every restart invalidates all sessions.

To force SSO-only once OIDC works, set `CRL_LOCAL_LOGIN_ENABLED=false` (the
break-glass admin still works for recovery).

## OIDC (authentik)

Register an OAuth2/OpenID Connect provider in authentik and set:

```ini
CRL_OIDC_ISSUER=https://<authentik-host>/application/o/<slug>/
CRL_OIDC_CLIENT_ID=...
CRL_OIDC_CLIENT_SECRET=...
CRL_OIDC_SCOPES=openid email profile
CRL_OIDC_GROUP_CLAIM=groups
CRL_PUBLIC_BASE_URL=https://crlmonitor.goodloe.xyz
```

The redirect/callback URL to register is:

```
<public-base-url><url-prefix>/api/auth/oidc/callback
```

i.e. for this deployment: `https://crlmonitor.goodloe.xyz/api/auth/oidc/callback`.

Set `CRL_PUBLIC_BASE_URL` so the callback URL is built reliably; otherwise it is
derived from the reverse proxy's `X-Forwarded-Proto`/`X-Forwarded-Host` headers
(which requires `TRUSTED_PROXY_HOPS` to match your proxy). The OIDC flow uses
`state` and `nonce` validation (handled by Authlib) on every login.

On first login an OIDC user is provisioned automatically (keyed on `sub`); email
and display name are refreshed from the token on later logins but are never used
for identity.

### Enabling authentik SSO — checklist

The **"Sign in with SSO"** button only appears when **all three** of
`CRL_OIDC_ISSUER`, `CRL_OIDC_CLIENT_ID` and `CRL_OIDC_CLIENT_SECRET` are set to
non-empty values. Setting the issuer alone gives you local login only.

1. **In authentik**, create an *OAuth2/OpenID Provider* and an *Application* bound
   to it. Note the **application slug** — the issuer is
   `https://<authentik-host>/application/o/<slug>/`, and the issuer you configure
   must belong to the **same** application whose client id/secret you use.
2. **Add the redirect URI** to that provider, exactly (https, no trailing slash):
   ```
   https://crlmonitor.goodloe.xyz/api/auth/oidc/callback
   ```
   (If you serve the app under a URL subpath, include it:
   `https://crlmonitor.goodloe.xyz/crl/api/auth/oidc/callback`.)
3. **Set the variables** in `.env` — one block, no duplicates:
   ```ini
   CRL_OIDC_ISSUER=https://<authentik-host>/application/o/<slug>/
   CRL_OIDC_CLIENT_ID=<from the provider>
   CRL_OIDC_CLIENT_SECRET=<from the provider>
   CRL_OIDC_SCOPES=openid email profile
   CRL_PUBLIC_BASE_URL=https://crlmonitor.goodloe.xyz
   CRL_SESSION_SECRET=<openssl rand -hex 32>
   ```
4. **Recreate the container** — an `env_file`/`environment` change does *not* apply
   on a plain `docker compose restart`:
   ```bash
   docker compose up -d --force-recreate crl-monitor
   ```
5. Reload the login page: you should now see local login **and** an SSO button.

**Troubleshooting "no SSO button":** a blank/commented or **duplicated**
`CRL_OIDC_*` value (a later line overrides an earlier one); or you ran `restart`
instead of `up -d --force-recreate` (step 4). All three values are mandatory.

**Troubleshooting "button works but login fails":** the issuer doesn't match the
application that issued the client id/secret, or the redirect URI in authentik
doesn't exactly match `…/api/auth/oidc/callback` at your public host.

> Treat `CRL_OIDC_CLIENT_SECRET` and `CRL_SESSION_SECRET` as credentials: keep them
> only in your secret store / `.env` (never commit them), and rotate them if
> exposed. Secrets are never written to the logs.

### Optional group restriction

By default any user who authenticates at the IdP may sign in. To limit access to
members of one or more authentik groups, set a comma-separated allowlist:

```ini
CRL_OIDC_ALLOWED_GROUPS=crl-operators,infra-admins
```

The group names are matched **exactly** (case-sensitive) against the user's group
claim (`CRL_OIDC_GROUP_CLAIM`, default `groups`; authentik's default `profile`
scope already emits group names). A user in none of the listed groups is denied at
the callback and is **not** provisioned. This app has no finer-grained roles — the
allowlist is all-or-nothing access.

## Reverse proxy & HTTPS

The app sits behind your TLS-terminating reverse proxy. For the `Secure` cookie
flag and the derived OIDC callback URL to be correct:

- keep `CRL_SESSION_COOKIE_SECURE=true` (the default) when served over HTTPS;
- set `TRUSTED_PROXY_HOPS` to the number of proxies in front of the app so the
  forwarded `Proto`/`Host`/`Prefix` headers are trusted (and can't be spoofed);
- set `CRL_PUBLIC_BASE_URL` to your external URL for a rock-solid callback URL.

## First admin before OIDC

There is no self-registration and no in-app user management UI. Create the first
(and recovery) admin purely from the environment:

```ini
CRL_SESSION_SECRET=$(openssl rand -hex 32)
CRL_BOOTSTRAP_ADMIN_USERNAME=admin
CRL_BOOTSTRAP_ADMIN_PASSWORD=<a strong password>
```

Recreate the container, then sign in with that username/password. Changing
`CRL_BOOTSTRAP_ADMIN_PASSWORD` and recreating the container resets the password —
a simple recovery path if you're ever locked out.

## Environment variable reference

| Variable | Default | Purpose |
|---|---|---|
| `CRL_ALLOW_OPEN_MODE` | `false` | Explicitly run with **no** auth (isolated/dev only). Required when no auth is configured, or the app refuses to start. |
| `CRL_SESSION_SECRET` | *(ephemeral)* | Signs session cookies. Set a stable random value in production. |
| `CRL_SESSION_COOKIE_SECURE` | `true` | `Secure` flag on the session cookie (HTTPS). |
| `CRL_SESSION_TTL_SECONDS` | `28800` | Session lifetime (8 h). |
| `CRL_SESSION_COOKIE_NAME` | `crlmonitor_session` | Session cookie name. |
| `CRL_LOCAL_LOGIN_ENABLED` | `true` | Allow local username/password login. |
| `CRL_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Break-glass admin username. |
| `CRL_BOOTSTRAP_ADMIN_PASSWORD` | *(empty)* | Break-glass admin password; setting it turns auth on. |
| `CRL_OIDC_ISSUER` | *(empty)* | OIDC issuer URL (authentik application). |
| `CRL_OIDC_CLIENT_ID` | *(empty)* | OIDC client id. |
| `CRL_OIDC_CLIENT_SECRET` | *(empty)* | OIDC client secret. |
| `CRL_OIDC_SCOPES` | `openid email profile` | Requested scopes. |
| `CRL_OIDC_GROUP_CLAIM` | `groups` | Token claim carrying group names. |
| `CRL_OIDC_ALLOWED_GROUPS` | *(empty)* | Comma-separated group allowlist (empty = any IdP user). |
| `CRL_PUBLIC_BASE_URL` | *(derived)* | Absolute external URL for building the OIDC callback. |

All three of `CRL_OIDC_ISSUER`, `CRL_OIDC_CLIENT_ID`, `CRL_OIDC_CLIENT_SECRET` are
required to enable OIDC. The `users` table is created automatically at startup.
