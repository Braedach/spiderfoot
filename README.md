# braedach/spiderfoot — fix fork

This is a fork of [poppopjmp/spiderfoot](https://github.com/poppopjmp/spiderfoot) holding a specific set of bug fixes to the AI report-generation and scanning pipeline, pending merge upstream.

**→ For the actual project — docs, issues, general use — go to [poppopjmp/spiderfoot](https://github.com/poppopjmp/spiderfoot).**

**Pending PR:** [poppopjmp/spiderfoot#393](https://github.com/poppopjmp/spiderfoot/pull/393)

## ✅ Known good build

**`6.1.0-gb05e98c3`** (commit `b05e98c3`), **2026-09-17** — fixes a real Postgres connection-leak bug in `6.1.0-g4b0231b2`
(this section's previous known-good build, now **not good — do not use**):
`ReportStore`'s read-only methods never committed or rolled back after a
`SELECT`, so a plain read could leave its transaction open indefinitely,
eventually blocking every later attempt to touch the `reports` table. From
the outside this looked exactly like AI report generation "just
spinning" — the report itself, and the LLM call, had already completed;
an unrelated stuck read was blocking everything downstream of it. See
`stack-spiderfoot-podman.yml`'s Changelog 2.4.0 for the full incident.

Fix verified in isolation (10 rounds of the affected methods left zero
stuck connections afterward, versus one per call before), and confirmed
live in production, **2026-09-17**: real AI reports generated
successfully end-to-end with no recurrence of the stuck-connection
pileup.

`6.1.0-g4b0231b2` itself was fully tested end-to-end on both Podman and
Docker deployments, **2026-09-13**: all services healthy, AI report
generation confirmed working, reports correctly persisted server-side
(scan-level and workspace-level) rather than only in the requesting
browser's `localStorage`, delete confirmed working, and the
scanner/active-scanner queue split confirmed correct on the Docker side
after a real bug was found and fixed there (a stale locally-cached base
image had silently been feeding 10-day-old code to three services despite
every build reporting success with zero errors). Tested via this fork's
own `Dev/spiderfoot-dev` stack files (`stack-spiderfoot-podman.yml` on
Podman, `stack-spiderfoot-docker.yml` on Docker) — the connection-leak bug
above was only found afterward, live on production, once real usage
actually exercised the code path.

## ⚠️ Breaking change

`requirements.txt` no longer installs `sentence-transformers`/`torch` **at all**, as
of image tag `6.1.0-g529d9da2` and every commit/build after it. If you have
`SF_EMBEDDING_PROVIDER=sentence_transformer` set anywhere, it will **silently**
degrade to mock (fake, hash-derived) embeddings via that backend's existing
`ImportError` fallback — no error, no warning, just quietly wrong report content.
Set `SF_EMBEDDING_PROVIDER=fastembed` instead (the new default in both compose
files below) — same job, no torch, ~67MB instead of ~1GB+.

## What's fixed here

- AI report generation returning empty/generic output (nine stacked bugs — service registry access, DB wiring, event-column mapping, Qdrant never populated, timeouts too short)
- Scan progress API (`/progress`, `/progress/stream`) returning 404 for every scan
- Local embeddings switched from `sentence-transformers`+`torch` (~1GB+, mandatory regardless of backend choice, per PyPI's own metadata) to `fastembed` (onnxruntime-backed, ~67MB, no torch anywhere) — real semantic search at a fraction of the size, with an optional `fastembed-gpu` build for deployments with GPU passthrough - NOT yet built as I dont need it - yet.
- Two Postgres connection leaks (`ConfigManager`, `AuthService`) — reads that never committed, leaving connections stuck open indefinitely
- Deleting a scan never cleaned up its vectors in Qdrant — fixed to delete by `scan_id` from the shared events collection
- AI reports silently capped at 500 analysed events per scan regardless of how many were actually indexed — now configurable (`SF_REPORT_MAX_EVENTS_PER_SCAN`), and both stack files now actually set it (`2000`) — the cap was configurable since 2026-09-13 but never actually raised anywhere, so it kept defaulting back to 500 regardless
- The generic `docker-compose.yml` + `docker/compose/*.yml` reference deployment had a real bug of its own: its general-purpose Celery worker still listened on the `scan` queue alongside the dedicated active-scanner worker, even though it lacks the recon tooling — scans could silently lose active modules depending on which worker claimed them
- AI reports generated via `sf-agents`' `/report` endpoint (the only path the frontend actually calls) were never persisted server-side — only ever reached the requesting browser's own `localStorage`, invisible from any other browser/device
- `ReportStore`'s read-only methods (`get`, `list_reports`, `count`) never committed after a `SELECT`, leaking a Postgres connection idle-in-transaction on every call — eventually blocks the whole `reports` table, surfacing as AI report generation appearing to hang
- The scan-summary "modules running" count always showed 0 regardless of actual scan state, because the field never existed anywhere in the progress pipeline — wired through end to end from the scan engine's existing internal module-tracking
- That alone wasn't enough: the scan engine's own "is this module running" check was blind to every module in the codebase (310/310), since the base check watches a shared thread pool that the actual per-module dispatch path never uses — not just cosmetic, since the same signal drives the scan-completion decision itself, not only the progress UI. Both confirmed live, **2026-09-18**.

See the PR for full detail on each.

## Deploying this fork

Three reference compose files, covering different use cases:

- **`docker-compose.yml`** (+ `docker/compose/*.yml`) — builds every image from source locally, Traefik-fronted, feature-profiled (`--profile full` for everything, or pick individual profiles: `ai`, `scan`, `storage`, `monitor`, `scheduler`, `sso`). Build the base image first (`docker compose build base`), then everything else — see that file's own header comment for why.
- **`stack-spiderfoot-podman.yml`** — the maintainer's own production Podman deployment. Pulls this fork's own pre-built, pushed images (`ghcr.io/braedach/spiderfoot/spiderfoot-*`) instead of building anything locally. No Traefik, no profiles — just the core services needed to run scans and generate AI reports. Genuinely Podman-compatible (standard Compose syntax throughout). Copy `stack-spiderfoot-podman.env.example` to a real env file and `litellm-config-podman.yaml` alongside it — see the compose file's own header comment for the full deployment sequence.
- **`stack-spiderfoot-docker.yml`** — builds every image from source via plain `docker compose`, no Traefik, no profiles, one flat file — useful for local dev/repro without the generic reference deployment's Traefik/profile setup. Copy `stack-spiderfoot-docker.env.example` to a real env file — see the compose file's own header comment for the full build/deploy sequence, including why the base image must be built first explicitly.

All three default local embeddings to `fastembed` — no API key, no GPU needed, though GPU passthrough is supported (see each file's comments) if you have it.
