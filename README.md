> 🔗 **Vaultwarden:** [github.com/dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)
>
> 📖 **Read the write-up:** [Self-Hosted Vaultwarden — Docker Setup, Clients & Full Guide](https://deb.myguard.nl/2026/05/self-hosted-password-manager-with-vaultwarden/)

# Vaultwarden (Bitwarden) OWASP CRS Plugin

![Integration Tests](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/integration.yml/badge.svg) ![Apache/v2](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/apache-modsecurity2.yml/badge.svg) ![NGINX/v3](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/nginx-libmodsecurity3.yml/badge.svg) ![NGINX/Coraza](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/coraza.yml/badge.svg) ![WAF Corpus](https://github.com/myguard-labs/vaultwarden-crs-plugin/actions/workflows/security-corpus.yml/badge.svg)

![Defense-in-depth: the vaultwarden-crs-plugin adds a PATH allowlist and false-positive exclusions at the WAF edge before requests reach the end-to-end encrypted Vaultwarden Rust backend and a hardened Docker container](https://deb.myguard.nl/wp-content/uploads/2026/07/vaultwarden-crs-plugin-defense-in-depth.webp)

A drop-in [OWASP CRS](https://coreruleset.org/) plugin that makes the Core
Rule Set play nicely with **[Vaultwarden](https://github.com/dani-garcia/vaultwarden)**
(the Rust Bitwarden-compatible server) — and, optionally, locks the host
down to Vaultwarden's known route map.

> **Why this differs from a form-app plugin.** Vaultwarden is a JSON API:
> the web vault, browser extensions, mobile, desktop and the Bitwarden CLI
> all POST `application/json` bodies whose argument **names** are JSON keys
> that vary per endpoint and per client version. A vimbadmin-style
> `ARGS_NAMES` allowlist would therefore false-block real clients. This
> plugin **deliberately ships no arg-name allowlist** — its positive-security
> layer is a **PATH allowlist** only. Bodies are end-to-end encrypted
> (EncString `2.<iv>|<ct>|<mac>` blobs + base64), so the before-rules strip
> the known-noisy base64/SQLi/PHP target families on the encrypted write
> paths rather than weakening the whole engine.

It does two things:

1. **False-positive exclusions** (`vaultwarden-before.conf`) — surgical,
   host-scoped exclusions so legitimate inputs (the Argon2 admin `token`,
   the OAuth password-grant hashes on `/identity/connect/token`, the
   EncString cipher/account/send blobs under `/api`, user-supplied icon
   domains) don't trip CRS.

2. **Positive security / path allowlist** (`vaultwarden-after.conf`,
   **opt-in**) — *allow Vaultwarden's real routes, deny everything else*.
   Any path outside Vaultwarden's mount points (`/api`, `/identity`,
   `/admin`, `/events`, `/icons`, `/notifications`, `/attachments`, the
   built-in static routes and the web-vault static tree) is denied. This
   stops the usual `/.env` / `/wp-login.php` scanner noise before it reaches
   the backend, regardless of payload. **No arg-name allowlist** (see above).

The route map is derived from Vaultwarden's source
(`src/main.rs` mount points + `src/api/web.rs` static routes) **and** the
bundled `web-vault` static tree extracted from `vaultwarden/server:latest` —
not guessed. It was last re-verified against source commit `169aa5e`.

The positive-security layer also: enforces an **HTTP-method
allowlist** (only `GET/POST/PUT/DELETE/HEAD/OPTIONS` — `TRACE`, `CONNECT`,
`PATCH`, junk verbs are denied, `9530220`); requires **`application/json`** on
`/api` writes (except multipart `/api/sends/file*` and cipher attachment
uploads, `9530225`); **anchors static-file extensions to a single path
segment** so a deep fake path like `/x/y/z.json` no longer slips through; and
**feeds the CRS inbound anomaly score** on every block, so fail2ban / CRS DOS
layers see the probe instead of a silent 404.

## Requirements

- CRS Version 4.0 or newer
- ModSecurity compatible Web Application Firewall

## Install

Copy the three files into your CRS `plugins/` directory:

```
plugins/vaultwarden-config.conf
plugins/vaultwarden-before.conf
plugins/vaultwarden-after.conf
```

CRS loads `plugins/*-config.conf`, then `*-before.conf` (before the rules),
then `*-after.conf` (after the rules) automatically.

## Configure

Edit `vaultwarden-config.conf`:

| Variable | Default | Meaning |
|---|---|---|
| `tx.vaultwarden-plugin_enabled` | `0` | Master on/off. **OFF by default** — the plugin weakens CRS on the Vaultwarden routes, so it must be enabled per vhost, not globally. Set to `1` only in the Vaultwarden server/location block (see Roll-out). |
| `tx.vaultwarden-plugin_positive_security` | `0` | **Independent** opt-in for the path-allowlist layer (`9530230`, plus the `9530220` method and `9530225` Content-Type rules). Does **not** follow `_enabled` — it denies by default, so an unknown route is answered 404; enable only after a DetectionOnly burn-in. **Changed in 2.2.0:** this used to follow `_enabled`, so upgrading deployments must now set it to `1` explicitly to keep the allowlist running. **Fixed in 2.2.1:** this flag no longer gates the CVE-driven rules `9530234`/`9530235`/`9530236` — they run whenever the plugin is enabled. |
| `tx.vaultwarden-plugin_argname_allowlist` | `0` | Experimental, **independent** opt-in for the arg-name allowlists (`9530240` token form fields, `9530245` GET query names). Does **not** follow `_enabled`; enable only after a DetectionOnly burn-in. |
| `tx.vaultwarden-plugin_admin_disabled` | `0` | **Independent** opt-in: deny `/admin` outright (`9530250`, returns 404). Removes the admin-panel RCE surface (CVE-2025-24364, GHSA-h6cc-rc6q-23j4). Does **not** follow `_enabled` — denying a real route must be a conscious choice. Turn on if you don't actively use the admin panel. |
| `tx.vaultwarden-plugin_basepath` | *(unset)* | Optional, only meaningful with `_positive_security=1`. When Vaultwarden is reverse-proxied under a single leading path segment (e.g. `https://host/vault/...`), set this to that segment (e.g. `vault`) so the route allowlist REQUIRES it instead of tolerating any one arbitrary segment. Unset (default) keeps the wildcard-tolerant route map, which accepts one fabricated leading segment by design (multi-segment basepaths need the prefix group in `9530230`/`9530231`/`9530232` widened by hand — see the comments in `vaultwarden-after.conf`). New rules `9530229`/`9530231`/`9530232`. |

### Advisory-driven rules

Three rules target specific upstream CVEs. They are defence in depth: a
patched Vaultwarden (≥ 1.36.0) already fixes all of them, but these hold the
line on an unpatched backend and survive a future bypass of the upstream fix.

| Rule | CVE | What it does |
|---|---|---|
| `9530235` | [CVE-2026-47160](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-72vh-x5jq-m82g) | Denies bare **IP literals** in the `/icons/<domain>/icon.png` path. The CVE was an SSRF where the private-address check ran on the string form while the resolver accepted decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`) and short-form (`127.1`) encodings of the same address. Rather than enumerate bypass encodings, the rule rejects the whole IP-literal class — a favicon domain is always a hostname. |
| `9530236` | [CVE-2026-47158](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-pfp2-jhgq-6hg5), [CVE-2024-55225](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-x7m9-mv49-fv73) | Denies **cross-site** requests to the SSO authorize/OIDC-callback routes, using `Sec-Fetch-Site` (browser-set, unforgeable by page JS). Requests with **no** `Sec-Fetch-Site` are allowed, so the Bitwarden CLI / mobile / desktop clients are unaffected — CSRF is a browser-only attack. `/identity/connect/token` is deliberately out of scope. |
| `9530250` | [CVE-2025-24364](https://bi-zone.medium.com/exploring-cve-2025-24364-and-cve-2025-24365-in-vaultwarden-562ee308270f), [GHSA-h6cc-rc6q-23j4](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-h6cc-rc6q-23j4) | Opt-in admin kill switch (see the toggle above). Both CVEs are post-auth RCE reachable only via `/admin`; removing the route removes the bug class. |

**Rate-limited advisories are handled at the edge, not here.** The
brute-force bypass ([CVE-2026-43914](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-c5rv-q295-7w4g)),
the 2FA rate-limit bypass (CVE-2026-27801), the SSO org-enumeration leak
(CVE-2026-47159) and the unauthenticated WebSocket flood fixed in 1.37.0 are
all *rate* problems. libmodsecurity3 has no persistent per-IP collections, so
these are covered by the `limit_req` zones in
[`contrib/angie/vault.conf`](contrib/angie/vault.conf), not by a SecRule.

The remaining advisories — cross-org access, collection/group authorization,
refresh-token rotation, WebAuthn verification ordering — are **not
WAF-addressable**: they are authorization bugs on requests that are
syntactically indistinguishable from legitimate ones. Patch the server.

Scoping is done entirely by the per-vhost enable flag — there is **no Host
gate**. Enable the plugin only on the Vaultwarden vhost, e.g. (Angie /
nginx + libmodsecurity3):

```nginx
server {
    server_name vault.example.com;
    modsecurity on;
    modsecurity_rules '
        SecAction "id:9530001,phase:1,nolog,pass,setvar:tx.vaultwarden-plugin_enabled=1"
    ';
    # ...
}
```

On Apache/mod_security2, set the same variable inside the matching
`<Location>` / `<VirtualHost>` block.

## Roll-out

1. Install, then enable the plugin in the Vaultwarden vhost only
   (`setvar:tx.vaultwarden-plugin_enabled=1`). The exclusions are safe
   immediately and never touch other vhosts on the same CRS engine.
2. Optionally add the path allowlist — it is a separate opt-in
   (`setvar:tx.vaultwarden-plugin_positive_security=1`), because it denies by
   default. Do this in the same block, then run CRS in **DetectionOnly** and
   watch the audit log for `9530230` hits — those are paths missing from the
   route allowlist. If you front Vaultwarden with extra routes (a
   reverse-proxy health check, a custom connector), add them to the inline
   allowlist regex on rule `9530230` in `vaultwarden-after.conf`.
3. Flip CRS back to blocking mode.

> **Upgrading to 2.2.0:** `tx.vaultwarden-plugin_positive_security` no longer
> follows `tx.vaultwarden-plugin_enabled`. If you were relying on the
> allowlist switching on with the plugin, add the explicit `setvar` from step
> 2 — otherwise the allowlist silently stops running after the upgrade.

> **Upgrading to 2.2.1 (security):** on 2.2.0 the opt-in above also switched
> off the CVE-driven rules that happen to share its ID range — `9530235`
> (icon-endpoint SSRF, CVE-2026-47160) and `9530236` + its `9530234` seeder
> (SSO CSRF, CVE-2026-47158). A deployment that set only
> `tx.vaultwarden-plugin_enabled=1` was therefore running **neither** CVE
> defence. 2.2.1 narrows the strip range so those rules always run with the
> plugin. No config change is needed; just upgrade. Also fixed: a
> `POST`/`PUT` to `/api` with **no** `Content-Type` header at all bypassed the
> `9530225` Content-Type check entirely (absent-variable fail-open).

> **Upgrading to 2.2.2 (security):** the JSON-API false-positive exclusion
> `9530103` was an unanchored path prefix, so a fabricated suffix —
> `/api/ciphersEVIL`, `/api/accounts-evil/x`, `/api/sendsEVIL` — also matched
> and stripped 284 CRS rules (the `platform-multi` and `attack-injection-php`
> tag families, spanning SQLi/XSS/Java/RCE/web-shells) on a path Vaultwarden
> does not route. Unlike the `9530105` case fixed in 2.2.1, the path allowlist
> does **not** compensate: `9530230` allows `api` as a mount and its trailing
> `(?:/.*)?$` swallows the fabricated suffix, so nothing else inspected these
> requests. Measured on both engines: a PHP-injection payload fires
> `933100`/`933130`/`933160`/`949110` on `/api/ciphersEVIL` and none of them on
> the real `/api/ciphers/import`.
> 2.2.2 end-bounds the regex; real routes and their subpaths keep the
> exclusion. No config change is needed; just upgrade.

Rule ID range: **9,530,000 – 9,530,999** (block base 9,530,000; free in the
[CRS plugin registry](https://github.com/coreruleset/plugin-registry),
pending formal assignment).

## Continuous integration

Every push/PR runs six GitHub Actions workflows (all but Lint get a badge above):

| Workflow | What it does |
|---|---|
| **Lint** | Rule-ID-range (9530000–9530999) / duplicate-ID / `@pmFromFile` / test-reference checks, then the official `coreruleset/crs-plugin-test-action` lint. |
| **Integration Tests** | Plugin-structure gates (no host gate, opt-in allowlist, **no `ARGS_NAMES` allowlist**, conditional config defaults, `ver:` on every rule). |
| **Apache/v2** | Runs the go-ftw regression suite on real Apache httpd + mod_security2 (`apache2ctl -t` gates parse). |
| **NGINX/v3** | Same suite on Angie + libmodsecurity3 3.0.14 — a production mirror (`angie -t` gates parse). |
| **NGINX/Coraza** | Loads every plugin file into `coraza.NewWAF()` then replays runtime transactions — Coraza fails hard at config load where ModSecurity warns, and load-OK ≠ fires (PRs only). |
| **WAF Corpus** | Replays real scanner/probe paths to prove the path/method allowlists deny them (regression guard for the trailing-slash + deep-nest bypass classes). |

The three-engine harness lives under [`tests/integration/`](tests/integration/);
go-ftw cases under [`tests/regression/`](tests/regression/) and
[`tests/security/`](tests/security/).

## Disabling the plugin

Set `tx.vaultwarden-plugin_enabled` to `0` (the default), or remove the plugin
files from the `plugins/` directory entirely.

## Edge hardening (rate limiting, native path/method allowlist)

The CRS plugin is the WAF half. For the **edge half** — per-endpoint rate
limiting (`/admin`, `/identity/connect/token`, register, send-download),
a native path allowlist that 404s unknown routes, a method allowlist, security
headers and body/timeout caps — see [`contrib/angie/vault.conf`](contrib/angie/vault.conf)
and [`contrib/README.md`](contrib/README.md).

Rate limiting in particular **cannot** be done in the plugin: libmodsecurity3
(v3) has no persistent per-IP collections, so it belongs at the edge (or in
fail2ban). Run the plugin and the contrib vhost together for belt-and-braces.

## Reporting false positives

Open a new issue or pull request. For issues, include:

- CRS Version
- ModSecurity/Coraza Version
- modsec audit logs
- what caused the false positive

## See also

- Vaultwarden: <https://github.com/dani-garcia/vaultwarden>
- Write-up / deployment guide: [Self-Hosted Vaultwarden on deb.myguard.nl](https://deb.myguard.nl/2026/05/self-hosted-password-manager-with-vaultwarden/)
- ViMbAdmin CRS plugin (same author, form-app variant with arg-name
  allowlist): <https://github.com/myguard-labs/vimbadmin-crs-plugin>
