# Upgrading SpiderFoot

This guide explains how to adopt a new SpiderFoot release and what to expect.
For the full list of changes see [`CHANGELOG.md`](CHANGELOG.md).

---

## Upgrading to rc.52 (from rc.51 or earlier): stack file settings for `sf-api`

**rc.52 needs a stack file change.** `sf-api` must have `SF_QDRANT_BACKEND=http`, `SF_QDRANT_HOST`, `SF_QDRANT_PORT`, `SF_QDRANT_GRPC_PORT`,
`SF_QDRANT_PREFIX` and `SF_AGENTS_URL=http://sf-agents:8100`; they are in `deploy/stack-podman.yml` 2.17.0 and `deploy/stack-docker.yml` 2.7.0. If you
manage the stack yourself, add them to the `sf-api` service (the stack file must come from the tag you deploy). Without them the AI report still
works, but search cannot reach the vector store. The optional AI report and indexing settings are in `sf-agents` with their defaults; see
`deploy/REFERENCE.md`, "AI report and search indexing". No database change.

- **First start.** `sf-agents` indexes every finished scan of the last 14 days (`SF_INDEX_RECENT_DAYS`) that is not indexed yet, one at a time at low
  priority. Expect it to use several CPU cores for a while on a deployment with many scans; set `SF_INDEX_AUTO=false` to turn it off.
- **Removed:** `POST /api/reports/generate` and `POST /api/reports/preview` (mock model, not used by the web page). Use `POST /api/agents/report`.
- **New:** `POST /api/rag/search` with a `scan_id` answers `202` with `indexed`, `total` and `percent` while that scan is being indexed;
  `GET`/`POST /api/rag/index/{scan_id}`.
- **The AI report** now reads a 900,000-character digest (`SF_REPORT_DIGEST_MAX_CHARS`). A report takes about three minutes on a 42,000-event scan.

## Upgrading to rc.51 (from rc.50 or earlier): old saved defaults no longer win

Saved module settings that equal a default a release has replaced (nikto and nuclei `max_targets` 20, naabu 50, nikto `total_budget` 7200, the
old arjun settings) are now ignored, so the current default applies for every scan, including one with your own module list. Nothing needs
resetting. A value you chose on purpose is kept, unless it is exactly a retired value. No stack file change.

---

## Upgrading to rc.50 (from rc.49 or earlier): old saved limits for nikto and naabu

rc.50 removes the count limits that made nikto test only the first 20 web servers and naabu scan only the first 50 hosts of a scan.
The shipped profiles (Full Footprint, Tools Only, Web Application Test, Network Service Test, IP Address) now pin the new values, so a scan
started from a profile is not affected by an older saved setting. **A scan started with your own module list still uses what is saved.** If your
deployment saved the old limits under Settings (they were stored as the defaults at first start), reset them to 0:
`sfp_tool_nikto` option `max_targets`, and `sfp_tool_naabu` option `max_targets`. No stack file change; set `SPIDERFOOT_TAG` and redeploy.

---

## Upgrading the fork build to rc.40 or later (from rc.39 or earlier)

**rc.40 removes 13 modules whose services are gone.** There is no stack file change and no database change; set
`SPIDERFOOT_TAG` and redeploy. The removed modules are `sfp_sublist3r`, `sfp_duckduckgo`, `sfp_bgpview`, `sfp_sorbs`,
`sfp_zonefiles`, `sfp_onionsearchengine`, `sfp_callername`, `sfp_trumail`, `sfp_searchcode`, `sfp_twitter`,
`sfp_threatminer`, `sfp_tool_wappalyzer` and `sfp_tool_phoneinfoga` (and `sfp_onioncity`, which needed a key and a service that
no longer answers). An API call, a saved schedule or a custom profile that names one of them will no longer find it:
remove the name. The shipped profiles already do not use them. Stored settings for them are ignored.

Optional: the person profiles use `sfp_searxng` only once you enter your own SearXNG address under Settings, Web Search.
From rc.41 an IP address scan stays on the address; from rc.42 it finishes. rc.43 was never published; go from rc.42 to rc.44. rc.46 was tagged but never published (its scan gate failed on the frontend image); go from rc.45 to rc.47, rc.48, rc.49 or rc.50.

---

## Upgrading the fork build to rc.35 or later

**rc.35 is a breaking change** for an existing stack. The steps, in order:

1. Take the stack file from the tag you are deploying (`deploy/stack-podman.yml` 2.16.0 or `deploy/stack-docker.yml`
   2.6.0, or later). It adds the `sf-tor` service. Changing only `SPIDERFOOT_TAG` leaves the stack running without it,
   and the dashboard then reports Tor as "not working".
2. Decide whether you want Tor. `sf-tor` is on by default and connects to the Tor network as soon as the stack starts,
   whether or not a dark-web scan runs; a firewall or IDS/IPS may flag or block that. To run without it, delete the
   `sf-tor` service from the stack file and turn off "Use Tor" under Settings, Tor. Dark-web modules then skip
   `.onion` pages.
3. Check Settings, Network & Proxy. The outbound proxy setting was ignored by earlier builds and now takes effect: if
   a proxy type, host and port are filled in, requests start going through that proxy. Clear them for a direct
   connection. The type `TOR` is still accepted there and is treated as SOCKS5, but Tor now has its own section.
4. Set `SPIDERFOOT_TAG` and **redeploy** the stack (not Stop and Start).
5. Check the dashboard's System health: Tor reads `checking` for up to a minute, then `working`. If it stays
   `not working`, read `podman logs sf-tor` (or `docker logs sf-tor`) and check that the host is allowed to reach Tor.
6. Expect different module counts on New Scan: "All Modules" leaves out error-prone and retired modules and includes the
   dark-web modules; "By Required Data" runs the modules that produce the selected data plus the modules that feed them
   (earlier builds ran every module); a profile applies its own thread limit and option overrides.

There is no database change and no host-side step. Scans launched before rc.35 show "Not recorded" for Module
selection in Scan Settings.

rc.34 fixes a database connection leak in rc.32 and rc.33 (the dashboard stopped updating and API calls answered 500
after about 15 minutes of use). Do not run rc.32 or rc.33.

## Upgrading the fork build (`v6.1.0-bd.1-rc.N`) to rc.31

This fork's builds are release candidates published by `deploy/publish.sh`; the build and deploy procedure is in
[`deploy/REFERENCE.md`](deploy/README.md). **rc.31 is a breaking change** for an existing stack:

1. Take the stack file from the same tag (`deploy/stack-podman.yml` 2.15.0 or `deploy/stack-docker.yml` 2.5.0). The stack
   files are not inside the images, so a new tag does not update them. The API and workers now need the embedding settings
   and the shared model cache.
2. On the host: `chown -R 1000:1000 /srv/spiderfoot/embeddings-cache`. The API and workers run non-root; without this the
   model download fails silently and embeddings fall back to meaningless `mock` vectors.
3. Set `SPIDERFOOT_TAG=v6.1.0-bd.1-rc.31` and **redeploy** the stack (not just Stop and Start, which reuses the old containers and image).
4. Scans now run on the Celery worker (2 at a time, extra scans wait in the queue). If a scan seems stuck in `STARTING`,
   check `sf-celery-worker-active`.
5. A stored `_embedding_provider` of `mock` overrides the new default. Set Embeddings to `fastembed` under Settings,
   AI & Search, and re-index scans indexed earlier.
6. Module API keys are now entered on the Modules page (`/credentials` redirects there).

## Upgrading to v6.1.0 (from 6.0.x)

**v6.1.0 is a hardening and test-maturity release.** There are **no breaking
changes**: no API, configuration, database-schema, or CLI changes. You can
upgrade in place.

- **No database migration is required** — the schema is unchanged.
- **No configuration changes are required** — existing `.env` / config files
  keep working.
- SpiderFoot remains **PostgreSQL-only** (since 6.0.0) and requires **Python
  3.10–3.13**.

### How to upgrade

Pick the path that matches your deployment.

#### Docker Compose (recommended)
```bash
git pull                      # get the v6.1.0 sources (or checkout the tag)
docker compose pull           # pull the rebuilt images
docker compose up -d          # recreate containers (add your profiles, e.g. --profile full)
```
Your PostgreSQL/Redis/MinIO volumes are preserved; existing scans and config
carry over.

#### Helm (Kubernetes)
The chart is **0.4.0** with `appVersion: 6.1.0`.
```bash
helm repo update
helm upgrade spiderfoot ./helm/spiderfoot   # or your chart repo reference
```

#### From source (pip / development)
```bash
git pull
pip install -r requirements.txt   # dependencies unchanged for 6.1.0
```

### Verify the upgrade
```bash
# Python package
python -c "import spiderfoot; print(spiderfoot.__version__)"   # -> 6.1.0

# Running API
curl -s http://localhost:8001/health        # readiness
# the API version endpoint also reports app_version 6.1.0
```

---

## Behavioural corrections to be aware of

v6.1.0 fixes several **silent correctness/security bugs**. The fixes are
improvements, but because they change how some events are *classified*, your
scan results may shift slightly compared with 6.0.x. None of these require
action — they are listed so the changes are expected, not surprising.

| Area | Before (6.0.x) | After (6.1.0) |
|------|----------------|---------------|
| **Private IPs** (`10.x`, `172.16–31.x`, `192.168.x`) | mislabelled as public `IP_ADDRESS` | correctly classified as internal (e.g. `sfp_dnsresolve` emits `INTERNAL_IP_ADDRESS`) |
| **Link-local** `169.254.169.254` (cloud metadata) and `fe80::/10` | treated as **public** | correctly treated as non-public |
| **Scan scope matching** | case-sensitive — mixed-case hosts (`Sub.Example.COM`) wrongly out-of-scope | case-insensitive — such hosts are now correctly **in scope** (you may see more in-scope results) |
| **URL de-duplication** | non-standard ports mangled (`:8080`→`80`), distinct URLs collided and dropped | port-aware — distinct URLs are preserved (you may see more distinct URL findings) |
| **Config booleans** | could flip `True`→`False` on an in-memory round trip | persist correctly |
| **Correlation rules** | one invalid regex aborted the whole correlation run | a bad rule is skipped with a warning; others still run |

### API endpoints fixed (were previously broken)
If you integrate against the REST API, these now behave correctly:

- `POST /api/data/modules/bulk-disable` — now accepts a JSON body
  `{"module_names": [...]}` (previously always returned `400`).
- `POST /api/storage/snapshots/all` — now snapshots all collections (previously
  hit the single-collection handler).
- Literal sub-paths that were shadowed by `/{id}` routes now resolve, e.g.
  `/api/notification-rules/{stats,history,operators,channels}`,
  `/api/report-templates/{history,variables,categories,formats}`,
  `/api/tags/{stats,colors}`, `/api/webhooks/event-types`,
  `/api/scans/compare`, `/health/shutdown`.
- Unknown-resource lookups that returned `500` now return the correct `404`
  (e.g. unknown module/entity/workspace/scan).

### Rollback
v6.1.0 introduces no schema or data-format changes, so you can roll back to
6.0.x by redeploying the previous image/tag — existing data remains compatible.

---

## General upgrade guidance

- Review [`CHANGELOG.md`](CHANGELOG.md) for the target version.
- Back up your PostgreSQL database before any major (`X.0.0`) upgrade.
- Major releases (e.g. a future `7.0.0`) may include breaking changes and will
  document required migration steps in this file.
