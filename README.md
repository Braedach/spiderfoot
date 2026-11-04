# braedach/spiderfoot — hardened fork

An internal-use fork of [poppopjmp/spiderfoot](https://github.com/poppopjmp/spiderfoot) (the microservices SpiderFoot, v6.1.0), kept public for licence reasons. It fixes bugs in the scanning and AI-report pipeline, replaces the build and deployment with a hardened, scanned, reproducible one, and is run by its maintainer for authorised OSINT and security testing.

**For the actual project — documentation, issues, general use — go to [poppopjmp/spiderfoot](https://github.com/poppopjmp/spiderfoot).** The one upstream PR ([#393](https://github.com/poppopjmp/spiderfoot/pull/393)) was closed unmerged: it had grown to 53 files mixing fork-specific infrastructure with genuine fixes, which is not reviewable as a single PR.

## Current state

- **Latest published build:** `v6.1.0-bd.1-rc.16`. It passed the scan gate on all 5 images: no fixable critical or high vulnerability and no unallowed secret (Trivy), plus an `npm audit` of the frontend dependencies. **Production (Podman, managed through Dockhand) runs `rc.16`.** No non-`rc` release has been cut yet; the first (`v6.1.0-bd.1`) follows once `rc.16` or a later build has soaked.
- **Validation in progress (`rc.16`).** The build is being exercised on production with one scan per kind of target, run with the maintainer's own or otherwise authorised identifiers: a phone number, an email address (two), a person's full name, and a public IP address, plus an AI report generated on an earlier scan. The aim is to cover each input type the scanner accepts and each module family it triggers, and to confirm that scans finish, correlations run, and the worker stays healthy. Results will be recorded here and in `deploy/README.md`. The ASN input type is not covered by this round.
- **Under investigation: active tool modules may follow a target outside its own scope.** On a domain scan, discovery modules (e.g. netblock/affiliate lookups, co-hosted-site discovery) produced hosts and addresses belonging to third parties (shared hosting, upstream providers), and active tool modules then ran against some of those addresses without a scope check gating them first. No active scanning of third-party infrastructure is authorised by the maintainer beyond what is needed to diagnose this. A fix (a central scope guard shared by every active module, default-deny for anything outside an explicit allowlist) is being designed; until it ships, active scans are being run and reviewed manually rather than left unattended. Target types exercised against this issue so far: **phone number, email address, domain, and person's name.** An **ASN search has not yet been tested** and is next.
what does that mean - if you are doing a domain search - ie.. your own - the scan may *escape* that domain and start including others that it is not authorised to examine.
- **Tag scheme:** `v<upstream base>-bd.<N>` for a release, `-rc.<M>` for a test build. An `-rc` tag never moves `:latest`.
- **Vulnerabilities:** every Dependabot alert has been reviewed; the few that remain are accepted with reasons (see below).
- **Long scans: fixed in `rc.16`, being validated.** On a crawl-heavy target a scan could keep running for hours after new findings stopped (a test scan was at 5.5 hours with 32 events in its last hour). Causes: `gobuster` ran once per discovered URL with no cap (989 URLs at about 11 an hour) and discarded everything it had found whenever a run timed out; the sibling per-URL tools capped runs but counted every URL *seen*, so `dalfox`'s cap was used up by URLs without parameters and `nikto` scanned a whole host once per page; and a worker without an init process left about 1,100 zombie Chromium processes after a screenshot-heavy scan. Now each tool runs once per real target (`gobuster` and `ffuf` per directory, `nikto` per web server, `arjun` and `dalfox` per endpoint), caps count runs, `gobuster` keeps partial results on a timeout, and the worker has `init: true`. On `rc.15` or earlier, note that aborting a scan skips the correlation step, so let a scan finish or run correlations afterwards if you need them.
- **Never push straight to `master`.** Work happens on a branch, goes through a pull request, and is tested as a release candidate before release.

## What is different from upstream

**Build and supply chain** (details in [`deploy/README.md`](deploy/README.md))
- Fork-owned Dockerfiles. Base images pinned by digest; Python dependencies hash-locked and installed with `--require-hashes`; every tool pinned by version and checksum. Rebuilding a tag gives the same image.
- A **14-day cool-down** on individually maintained software, with named, written exceptions for published security fixes. Official OS base images are exempt and refreshed deliberately.
- A **scan gate** that blocks a push: Trivy fails the build on any fixable critical or high vulnerability or unallowed secret, Grype cross-checks, and `npm audit` covers the frontend's bundled dependencies (which the container scanner cannot see). Accepted findings live in `deploy/trivyignore.txt` with a justification; it is currently empty.
- Images are scannable (the package list is kept, the package managers are removed), and unused binaries are removed rather than waited on.
- The active-scanner image builds its Go tools from source with their vulnerable dependencies raised, and drops tools whose own dependencies could not be fixed.
- Builds run on a dedicated build host with `deploy/publish.sh`; production only ever pulls the published images. `publish.sh` reads the build token from one root-only file, removes its own project's local images before a build and on any exit, and refuses to start with under 12 GB free.

**Scanning and correctness fixes**
- **Correlation rules** were never loaded by the API, so no scan produced correlation results; they now load from the filesystem, verified end to end on a real scan.
- **Tool modules:** five tool modules (gobuster, testssl.sh, whatweb, wafw00f, snallygaster) had no binary path configured anywhere, and gobuster had no default wordlist; both now default to the paths baked into the image. A single-page app's catch-all `200` no longer turns every wordlist entry into a hit (`ffuf` auto-calibration, a soft-404 probe for gobuster). `naabu`, `dnsx`, `httpx` and the spider now work against internal hostnames and non-default ports.
- **Core URL helpers** (`urlBaseUrl`, `urlRelativeToAbsolute`) were dropping explicit ports and mangling `scheme://`, corrupting every link a crawl discovered.
- **Scan engine and API:** the scan-progress API returned 404 for every scan; the "modules running" count was always 0 because the engine's own running-module check was blind to every module; the export endpoints crashed or silently returned nothing; configuration saved on one API worker was not visible from the others.
- **Database:** Postgres connections were leaked by reads that never committed (`ConfigManager`, `AuthService`, `ReportStore` and 17 more methods in the core database layer), eventually blocking the whole API.

**AI reports**
- Report generation returned empty or generic output (nine stacked bugs across service access, database wiring, event mapping, vector indexing and timeouts). Reports are now persisted server-side, the analysed-event cap is configurable (`SF_REPORT_MAX_EVENTS_PER_SCAN`), and deleting a scan removes its vectors.
- Local embeddings use `fastembed` (about 67 MB, no GPU needed) instead of `sentence-transformers` and `torch` (over 1 GB). GPU passthrough is supported but not built.
- `sf-agents` calls Anthropic directly through the official SDK (no proxy), with a server-side fallback model for requests the primary model's safeguards decline.
- **AI Connections:** the LLM provider (Anthropic, OpenAI, DeepSeek, Ollama or Mock), its API key and its model are set **only in the GUI**. There is no LLM API key in the environment variables any more: the stacks, env templates and bootstrap script no longer carry one. Keys are stored encrypted and never shown again; the model is chosen from the list the provider offers. One provider is active at a time, with no automatic fallback between providers, so scan findings only go to the one you chose. See [`deploy/README.md`](deploy/README.md) for the details. Ollama needs a network route from `sf-api` and `sf-agents`: see "Ollama and the LLM network" in [`deploy/README.md`](deploy/README.md), which also explains why the maintainer's production stack reuses an existing `llm-net`.

**Frontend**
- A dedicated Data Source Credentials page and an AI Connections page; Settings grouped by subsystem; SpiderFoot's own REST tokens renamed "Access Tokens" to stop clashing with module API keys.
- New Scan dims modules that cannot run against the chosen target type.
- The workspace IaC Map diagram renders (it was blank, a sanitiser stripped the SVG), and several authorisation-redirect and race-condition bugs are fixed.

## Breaking change

**rc.15: the LLM API key is no longer an environment variable.** Upgrading from rc.14 or earlier requires: (1) replace the stack file (the old one *requires* `ANTHROPIC_API_KEY` and does not pass the JWT secret to `sf-agents` and the workers); (2) redeploy on `rc.15`; (3) sign in as an administrator, open **AI Connections**, enter the provider key, choose a model and make the provider active; (4) delete `ANTHROPIC_API_KEY` from the stack environment. Until a key is saved there, AI reports fail with a message pointing at AI Connections. Keys are encrypted using a key derived from `SF_JWT_SECRET_KEY`, so rotating that secret means entering them again.

**Earlier:** `requirements.txt` no longer installs `sentence-transformers` or `torch` at all. If `SF_EMBEDDING_PROVIDER=sentence_transformer` is set anywhere it will **silently** fall back to fake, hash-derived embeddings, with no error and quietly wrong report content. Set `SF_EMBEDDING_PROVIDER=fastembed` (the default in both stack files).

## Deploying this fork

Two layers, deliberately separate:

- **Upstream's own deployment**: `docker-compose.yml` and `docker/compose/*.yml` build every image from source, Traefik-fronted and feature-profiled (`--profile full` for everything, or pick `ai`, `scan`, `storage`, `monitor`, `scheduler`, `sso`). Build the base image first (`docker compose build base`); see that file's header for why. This fork patches some of these files but otherwise leaves them alone.
- **`deploy/`**: this fork's own tooling, in its own folder so pulling upstream never conflicts with it.
  - `deploy/publish.sh` builds the 5 images from an explicit tag on the build host, runs the scan gate, pushes `ghcr.io/braedach/spiderfoot-<service>:<tag>`, and creates a GitHub Release.
  - `deploy/stack-podman.yml` is the production deployment: it pulls the published images and builds nothing.
  - `deploy/stack-docker.yml` is the Docker development mirror, where release candidates are tested first.
  - Both stacks require an exact `SPIDERFOOT_TAG` and never follow `:latest`.

See [`deploy/README.md`](deploy/README.md) for the build, test and release flow, the tag scheme, how each secret is generated, and the dated record of what was fixed in each build.

## Dependabot and vulnerability review

Every Dependabot alert on this repository has been reviewed, and corrective action has been taken wherever a fix exists. Reviewed **2026-11-03/04**; 233 alerts were open when Dependabot was enabled, **9 remain**, none critical and none high in anything that ships.

What was done:
- Frontend npm dependencies (143 alerts) were patched with the 14-day cool-down respected, plus two named security exceptions (`follow-redirects`, `vite`). They were an unscanned gap, because the container scanner cannot see inside the minified JS bundle, so `deploy/publish.sh` now runs `npm audit` against the lockfile and fails the build on a high or critical runtime finding.
- Upstream's stale `Pipfile`/`Pipfile.lock` (86 alerts; no image has ever installed from them) were removed. The images install from the hash-locked `deploy/requirements.lock`.
- Python image dependencies are gated by Trivy on every build; nothing is published with a fixable critical or high finding. See `deploy/README.md` for the build history.

The 9 that remain are real advisories, not false positives, and are accepted for these reasons:

| Alerts | Package | Severity | Why accepted |
|---|---|---|---|
| 6 | `js-yaml`, `@hey-api/openapi-ts`, `minimatch` | 3 high, 3 medium | Frontend **dev tooling only** (API client generator, linter). Never copied into the image: the frontend image contains only the built static assets. The generator is also a required peer of the generated API client, so it can only move together with a regenerate-and-compare migration (to 0.99); the linter fix needs eslint 10. Tracked as separate work. |
| 2 | `setuptools` | 1 low, 1 medium | Build tooling pinned at 82.0.1 in the image lock. The advisories are Windows (`namespace_packages.txt` path escape) and macOS (sdist `MANIFEST.in` Unicode collision) specific, so they do not apply to the Linux images. The fix (84.1.0) is now old enough for the cool-down, but is a two-major jump in build tooling: to be done as its own tested change, not bundled in. |
| 1 | `paramiko` | low | `rsakey.py` permits SHA-1 for RSA signatures. No patched version exists upstream. Revisit when one is published. |

The test runner (`vitest` 5, which cleared the two critical `tinypool` alerts) and `mermaid` 12 (which cleared the `katex` alert) were upgraded on 2026-11-04.
