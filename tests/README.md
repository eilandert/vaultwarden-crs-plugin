# Test harness notes

Two engines, one shared CRS+plugin image:

| Engine | Port | Stack |
|---|---|---|
| Apache | 8001 | `mod_security2` |
| Angie  | 8002 | `libmodsecurity3` |

```bash
docker compose -f tests/integration/docker-compose.yml build crs      # build crs FIRST
docker compose -f tests/integration/docker-compose.yml build apache nginx
docker compose -f tests/integration/docker-compose.yml up -d apache nginx
sudo chmod -R a+rX tests/logs                                         # audit.log is root-owned
./ftw run -d tests/regression --config tests/integration/.ftw.yml
```

`tests/regression` + `tests/security` are the CI merge gate.
`tests/accepted-residual` is **outside** the gate — those cases fail by design.

## `retry_once: true` — why every stage has it

Every stage in `tests/regression` and `tests/accepted-residual` sets
`retry_once: true`. This is a workaround for an **upstream go-ftw race**, not a
weakness in the rules, and it should not be removed.

### The bug

`SecAuditLogType Serial` writes the audit entry *after* the response is sent,
and entries can be flushed out of order (visible as non-monotonic `unique_id`
values in `audit.log`). go-ftw brackets each test with marker requests, and
`CheckLogForMarker` scans the log **backwards**, taking the **first**
`X-CRS-Test` line it finds. If the current marker has not been flushed yet, that
first line is the *previous* test's marker, the stage ID does not match, and the
start marker is never found:

```text
DBG found unexpected marker line while looking for 9530230-6-...-s: ... 9530230-5-...-e
DBG start marker not found while collecting marked lines
```

`getMarkedLines` then returns a truncated window and a perfectly good
`expect_ids` assertion fails — always on a random test untouched by whatever was
being changed, always clearing on re-run. That signature is the tell.

Upstream: [go-ftw#473](https://github.com/coreruleset/go-ftw/issues/473) (open,
"Log flushing not reliable") and
[go-ftw#501](https://github.com/coreruleset/go-ftw/issues/501), where the
maintainers confirm it is known and recommend exactly this option.

### Why `retry_once` is the right fix

It re-sends the stage with fresh markers. A flush race does not reproduce, so it
passes; a genuine regression *does* reproduce, so it still fails. Sabotage-verified:
neutering the `9530220` method regex still fails the suite with `retry_once` on
(`Retrying test once: 9530220-1` → `Error: retry-once`).

Measured on the 32-core builder, `worker_processes auto`:

| Configuration | Failures |
|---|---|
| baseline | ~1 run in 3 to 1 in 25 |
| **with `retry_once`** | **0/40 nginx, 0/15 apache** |

### What does NOT fix it — do not retry these

- **A stronger readiness gate.** The race is per-test and mid-suite; it happens
  on long-warm containers. Verified: the rule engine logs immediately once the
  old `curl /` gate releases (5/5).
- **`worker_processes 1`.** Still fails — it is not multi-worker contention.
- **`--rate-limit`.** Still fails.
- **Raising `--max-marker-retries`.** Makes it **worse** (4/40): every retry
  appends another marker line for the backwards scan to trip over.
- **Truncating `audit.log` between runs.** Reduces but does not eliminate it;
  log volume is an aggravator, not the cause.

## Other harness traps

- **Engine-layer rejections are not rule hits.** nginx answers `TRACE` 405 and a
  lowercase `get` 400; both servers 400 an escaping traversal before ModSecurity
  runs. Assert only what actually reaches the rule.
- **HTTP status is not the signal.** The backend stub 200s almost everything.
  Decide with `expect_ids`/`no_expect_ids`, never the response code.
- **go-ftw injects a default `Content-Type`**, so an absent-header case cannot be
  expressed — documented in `9530225.yaml` rather than faked.
- **Build `crs` before `apache`/`nginx`**, and `sudo chmod -R a+rX tests/logs`
  before every run.
