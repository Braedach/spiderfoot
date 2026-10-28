# deploy/

A personal deployment setup for this fork — a build script that publishes
versioned images + a GitHub Release, and Compose stacks to run them.
Separate from the rest of the repo on purpose (its own subfolder, touches
nothing upstream owns) so pulling future changes from upstream never
conflicts with it. It follows the same pattern as the maintainer's other
forks (ARTEX was the first).

Nothing here is required to use SpiderFoot itself — see the root
`README.md` and upstream's `docker-compose.yml` for the general install
paths. This is specifically how *this* deployment builds and runs it.

## Layout

```
deploy/
├── publish.sh                  # build + push + release — run on the build host only
├── stack-podman.yml            # PRODUCTION deployment (Podman host)
├── stack-podman.env.example    # tracked template — names only, no real values
├── stack-docker.yml            # DEVELOPMENT / sandbox deployment (Docker host)
├── stack-docker.env.example    # tracked template — names only, no real values
├── bootstrap-spiderfoot-env.sh # generates the real env file (secrets) once per deployment
├── scan-gate.sh                # Trivy + Grype gate publish.sh runs on every image
├── docker/                     # fork-owned Dockerfiles (base, frontend, active-scanner, go-build.sh)
└── requirements*.in / .lock    # hash-locked Python: the app, and the active scanner's tools
```

Both stacks run the same 8 services (7, plus the active-scan worker under the `scan` profile) and only ever **pull** images. They never
build anything. The development stack mirrors production on purpose: what is
tested there is what runs here.

## Why the old Docker stack was replaced

`stack-spiderfoot-docker.yml` (v1.11.0, last updated 2026-09-22) was replaced
rather than patched, on 2026-10-23. It was a different design from what actually
runs in production, and a development stack that does not mirror production
cannot tell you whether a change is safe to release:

- **It built from source on the deploy host.** The pattern this fork follows
  builds on a dedicated build host and only *pulls* finished images on the host
  that runs them, so the machine running the stack never builds anything.
- **It ran 11 services, production runs 9.** It carried MinIO (with its init
  job) and Tika, which production does not run, so those paths were exercised
  in development and never in production, and the reverse was untested.
- **It used named volumes and its own env layout** (CPU/memory limit variables,
  MinIO credentials), while production bind-mounts state under
  `/srv/spiderfoot` with the env file described below. A deployment that
  differs in how state is stored differs in how it fails.
- **It had drifted behind production**, which had moved on through several
  fixes (image sources, required tags, hardening) that the Docker stack never
  received.

The replacement, `stack-docker.yml`, is derived from the production stack and
differs only where Docker and Podman genuinely differ (no CDI GPU device, no
dashboard labels). The old file is not kept: it remains in git history
(`git log --follow -- deploy/stack-docker.yml`). MinIO, Tika and the other
profiles are still available through upstream's own `docker-compose.yml`, which
this fork does not modify.

## The flow: branch → test build → release

Nothing is pushed to `master`. Work happens on a branch, is tested as a
**release candidate** on the development host, and only then merged and
released.

| Step | Where | Command / action |
|---|---|---|
| 1. Develop | workstation | branch off `master`, commit, push the branch, open a PR (do not merge yet) |
| 2. Test build | build host | tag the branch tip `v6.1.0-bd.1-rc.1`, `git push origin <tag>`, then `./deploy/publish.sh v6.1.0-bd.1-rc.1` |
| 3. Soak | development host | set `SPIDERFOOT_TAG=v6.1.0-bd.1-rc.1`, `docker compose … pull && up -d`, test |
| 4. Merge | GitHub | merge the PR once step 3 is satisfactory |
| 5. Release | build host | tag the merged commit `v6.1.0-bd.1`, push it, `./deploy/publish.sh v6.1.0-bd.1` |
| 6. Deploy | production host | set `SPIDERFOOT_TAG=v6.1.0-bd.1` in the stack's environment and redeploy |

### Tag scheme

`v<upstream base version>-bd.<N>` for a release, `…-rc.<M>` appended for a test
build. Bare `vX.Y.Z` tags are **upstream's** namespace (upstream already owns
`v6.1.0`) and `publish.sh` refuses them. A release tag moves `:latest`; an
`-rc` tag **never does**, so a test build cannot reach anything that follows
`:latest`. The stacks do not follow `:latest` anyway: `SPIDERFOOT_TAG` is
required and has no default.

## Build + publish

```bash
./deploy/publish.sh v6.1.0-bd.1-rc.1      # test build
./deploy/publish.sh v6.1.0-bd.1           # release
./deploy/publish.sh v6.1.0-bd.1 --check   # status only
```

Builds the 5 images (`base`, `api`, `scanner`, `active-scanner`, `frontend`),
verifies each image's revision label equals the commit being shipped, pushes
`ghcr.io/braedach/spiderfoot-<service>:<tag>`, and creates a GitHub Release
(a *pre-release* for `-rc`) carrying the pushed image digests.

**Needs:**
- `git`, `docker` and the `gh` CLI on the build host — nothing else. The
  Python, Node, Go and C toolchains all run inside the Dockerfiles' own
  build stages.
- a **classic** GitHub PAT, `write:packages` + `repo` scope (GHCR push does
  not work reliably with a fine-grained PAT, regardless of the scopes
  granted). It is **not** limited to this repository — see "Token scope"
  below
- the tag already pushed to `origin`
- a clean clone dedicated to publishing — it checks the tag out in place
- roughly 30GB free disk and 6GB RAM: `active-scanner` compiles Go and C tools
  from source, and a cache-cold build can take over 20 minutes

The token is prompted for the first time, or read from
`../.spiderfoot-publish/.ghcr-token` — a directory **beside** the clone, never
inside it (chmod 600). `publish.sh` refuses to run if that state directory is
inside the repo. Never pass the token as an argument or env var, and never
commit it.

**Token scope.** A classic PAT with `repo` can read and write *every*
repository the account can reach, private ones included; it cannot be narrowed
to one repo (only fine-grained tokens can, and those do not work for GHCR
pushes). Whatever host holds it therefore holds that access. Use a token
created only for this, keep it only on the build host, give it an expiry, and
rotate it.

**One-time GitHub setup:**
- A brand-new image name is created **private** on GHCR; flip it to Public
  once in the package settings. The 5 names above already exist.
- Keep the inherited GitHub Actions publish workflows (`docker.yml`,
  `release.yml`) **disabled** in the fork's Actions settings. `publish.sh` is
  the only supported publisher; a tag push would otherwise trigger upstream's
  own publish jobs.

## Supply-chain policy

Written after a baseline scan (2026-10-23) of the images production was running
found the active-scanner at 42 critical / 985 high findings, the frontend at 2 /
57, and secrets-scanning noise from a bundled exploit repository. The causes
were structural, so the fixes are rules, not one-off patches:

- **The tag pins SpiderFoot's source, nothing else.** The old Dockerfiles pulled
  16 Go tools at `@latest`, six repositories at branch HEAD, unpinned pip and npm
  packages and wordlists from moving branches, so rebuilding the same tag
  tomorrow gave a different image. Everything the fork-owned Dockerfiles install
  is now pinned: base images by digest, Python by exact version **and hash**
  (`deploy/requirements.lock`, `pip install --require-hashes`), tools by version.
- **A 14-day cool-down applies to individually maintained software.** Do not
  adopt a release younger than 14 days: a hijacked maintainer account is caught
  within days, not hours (the March 2026 Trivy compromise lasted about three
  hours; its malicious container images about ten). Lock compilation enforces it
  (`--exclude-newer`).
- **...except for a published security fix, as a named, written exception.**
  Taken so far: `certifi` and Pillow 13 (critical CA-trust and image-decoding
  findings), and on 2026-10-24 `brotli` 1.2.1 (critical), `filelock` 4.2.1 and
  `pypdf` 6.21.2 (high), plus the `cryptography` override in the tools lock. Each is
  an `--exclude-newer-package` date in the compile command below, and must pass the
  scan gate. Move them back under the 14-day rule at the next rebuild.
- **...and official OS base images are exempt.** `node`, `nginx`, `python`,
  `debian` are rebuilt every day or two as patches land, so an old build is a
  *less* patched build. They are pinned by digest and refreshed deliberately; the
  scan gate is their control.
- **Nothing is pushed unless every image passes the scan gate**
  (`deploy/scan-gate.sh`): no fixable critical/high vulnerability and no unallowed
  secret, by Trivy; Grype cross-checks and is reported. Accepted findings live in
  `deploy/trivyignore.txt`, each with a written justification. The scanners are
  themselves pinned by digest.
- **An unfixable CVE in an unused binary is removed, not waited on** (e.g. curl in
  the frontend image).
- **Images must be scannable.** Upstream's base deleted the package database, so
  its OS packages were invisible to scanners and "0 findings" meant "can't see".
  The fork-owned base keeps the read-only package list and removes the package
  managers.
- **Rebuild on a schedule, not only on commits.** Upstream has had no commit since
  2026-06-02, yet OS packages and dependencies keep acquiring CVEs. A release
  number (`-bd.N`) is a *build* number: cut a new one at least monthly.

Known dependency overrides (`pip check` will say so; expected, and tested): Pillow 13
although fastembed declares `<13` (`requirements-overrides.txt`), and `cryptography` 50
for sslyze (`requirements-tools-overrides.txt`).

### Active scanner

`docker/Dockerfile.active-scanner` replaces upstream's. Everything is pinned
and checksum-verified; Python tools live in their own hash-locked venv.

- **Go tools** are built by `docker/go-build.sh` with their vulnerable
  dependencies raised to the floor list in the Dockerfile (`GO_FLOORS`), and
  nuclei is built from source on the current Go. The first scan found 2 critical /
  112 high, all inside binaries' embedded dependencies. When the gate reports a new
  one, raise the floor to the first fixed release (at least 14 days old, or a named
  exception). gowitness is built from a checkout (its `go.mod` has `replace`
  directives); gau is pinned to a commit.
- **Removed:** amass (own dependencies carry 2 critical / 48 high; v5 is a different
  architecture; subfinder + dnsx cover it), gospider and hakrawler (katana),
  waybackurls (gau), LinkFinder (katana `-jc`), CMSeeK (whatweb, httpx), retire.js
  (never worked). **Replaced:** PyPI `trufflehog` (abandoned v2) by TruffleHog v3.
  Their modules still exist and report "binary not found".
- **Runtime needs** (set in the stacks): `HOME=/home/spiderfoot` (the stacks run it
  as uid 1000, which has no passwd entry) and tmpfs over `.config`, `.cache` and
  `.pdcp`, or katana and nuclei exit without scanning. `cap_add: NET_RAW` and
  `no-new-privileges: false` for this worker only: nmap, naabu and masscan carry
  `cap_net_raw` as a file capability, which the kernel ignores for a non-root
  process while no-new-privileges is on (tested). massdns needs none.
- **Module paths:** most tool modules default to blank and auto-search `PATH`.
  Five don't - `gobuster`, `testssl.sh`, `whatweb`, `wafw00f`, `snallygaster`
  require an explicit `*_path` with no fallback, and nothing anywhere had ever
  set one (see the dated entry below); their defaults now point at the real
  path baked into this image (e.g. `/tools/testssl.sh/testssl.sh`).
- **Testing an image:** run each tool module against a local server with the
  stack's exact container flags (`--read-only`, `--user 1000:1000`,
  `--cap-drop ALL --cap-add NET_RAW`, the tmpfs mounts). That found a dozen
  modules written for old command lines (dalfox, gowitness, gobuster, tlsx,
  arjun, TruffleHog) and the HOME / capability problems above.
- **Internal targets need their own DNS and port handling.** Found by a real
  end-to-end scan against `sf-juiceshop` (below): `naabu` and `dnsx` ship their
  own bundled resolvers and cannot see a Docker/Podman compose hostname at
  all (`naabu`: `-system-resolver` added, a pure fallback; `dnsx`: pointed at
  the container's own resolver via `-r`, since its flag replaces rather than
  falls back). Separately, `httpx` and `sfp_spider` only ever probed/crawled
  their fixed default ports (`80,443,8080,8443` for httpx; the implicit
  default for the spider) and never acted on a port a scanner actually found
  open, so a web app on anything else (Juice Shop: 3000) was invisible to
  every tool downstream of them; both now also watch `TCP_PORT_OPEN` and act
  on exactly that port (4 events on the first scan -> 9 with the tool fixes
  alone -> full crawl with `sfp_spider` fixed too).
- **Two core URL helpers were corrupting every link a crawl discovered**,
  independent of port: `SpiderFootHelpers.urlBaseUrl()` dropped an explicit
  port entirely (so a link resolved against it pointed at the wrong port),
  and `urlRelativeToAbsolute()` split the *whole* URL - scheme included - on
  `/` and dropped empty segments, which also dropped the empty segment
  between the two slashes of `scheme://` (`"http://host/x"` ->
  `"http:/host/x"`) and let a long enough run of `../` eat into the domain
  itself once it ran out of path to pop. One test file had been updated to
  assert the bug's own output as correct instead of the bug being fixed;
  both are fixed now, with tests asserting the correct result. See
  `spiderfoot/helpers.py`.
- **A single-page app's catch-all 200 made every path-fuzzer wordlist entry a
  false hit.** Juice Shop, like most Angular/React/Vue apps, serves its index
  page with HTTP 200 for any path at all (client-side routing fallback) -
  confirmed by requesting a random nonexistent path directly. `gobuster`'s and
  `ffuf`'s own status-code filters can't tell that from a real hit, so nearly
  every entry in a ~4,750-word wordlist "hit", each spawning its own
  downstream crawl/probe - a scan that should take minutes ran for 16+ hours.
  `ffuf` has auto-calibration built in (`-ac`, now on by default); `gobuster`
  doesn't, so it gets a probe-one-random-path-first check instead
  (`soft_404_detection`, default on), passed to its own `--exclude-length`.
  Checked the same class of bug in every other wordlist-driven tool module:
  `arjun` (parameter discovery) correctly found nothing on the same target,
  by design - its own response-diffing isn't fooled by an identical response
  regardless of parameter; `sfp_tool_massdns` has no wildcard-DNS defence of
  its own, but nothing in the current `tools-only` profile feeds it a bulk
  candidate list, so this is a flagged, currently-dormant risk, not fixed.
- **`v6.1.0-bd.1-rc.5`: the first build that produces real, trustworthy results
  end to end**, not just a clean scan gate. A full `tools-only` run against
  Juice Shop went from never finishing (16+ hrs, aborted at 22,665 events, on
  `rc.4`) to `FINISHED` in ~40 minutes with 839 varied, plausible events across
  ten modules (`rc.5`) - the gobuster/ffuf fix above plus everything in the
  commits before it, proven by actually running the thing, not just by the
  gate passing.
- **2026-10-25: five tool modules had no binary path configured, anywhere, ever.**
  `gobuster`, `testssl.sh`, `whatweb`, `wafw00f`, `snallygaster` all errored
  "did not set a path to the tool" during a live external scan. This looked
  like a scan-profile artifact (the scan used a hand-built module list rather
  than a named profile) but wasn't - traced `api/routers/scan.py` through
  `scan/scanner.py` and confirmed a profile only ever selects *which* modules
  run, never their options, so no profile choice could have fixed this.
  These five modules, unlike most others here, ship with no `PATH` fallback
  and require an explicit path; a direct query of `tbl_config` on Postgres
  confirmed none had ever been set, in any profile, on any scan - including
  `rc.5`'s own Juice Shop run, which hit the identical five errors unnoticed.
  Fixed by baking the real, confirmed binary paths from this image into each
  module's own default `opts` (`/tools/bin/gobuster`,
  `/tools/testssl.sh/testssl.sh`, `/usr/bin/whatweb`,
  `/opt/venv-tools/bin/wafw00f`, `/opt/venv-tools/bin/snallygaster`). Full
  module suite (1387 passed) clean after. Not in any built image yet - lands
  in the build after `rc.5`. `wappalyzer`'s gap is unrelated (needs an API
  key, not a path) and is a user decision, not a code fix.
- **2026-10-25: `rc.5` proven end to end against two real targets.** OWASP
  Juice Shop (`rc5-juiceshop`): `FINISHED`, ~40 minutes, 839 events. Then a
  live, authorised external target, `demo.testfire.net` (`rc5-demotestfire-pass1`,
  the 27-module HTTP/DNS/TLS-only set, port-scanners deliberately excluded for
  this first pass): `FINISHED`, ~2 hours, 5,324 events, with the UDM SE
  gateway's IDS/IPS watched live throughout and clean the whole run. Both runs
  surfaced the five-tool path-default gap above, now fixed. With the backend
  now validated on real targets, work has moved to the GUI: a Settings/API-key
  cleanup is underway (see "Frontend" below), and further validation passes
  (a port-scanner pass against `demo.testfire.net`, more external targets) are
  still to come.
- **Accepted, not fixed:** gosu (Go 1.24.6) in every Postgres image and Node
  packages in Qdrant's SBOM file: neither is ours to patch; revisit when the
  maintainers ship. Grype's openssl findings are Debian-backport false positives.

### AI model

`sf-agents` uses `claude-sonnet-5-5` (`SF_LLM_MODEL`). Anthropic's safeguards on it can decline a request
(HTTP 200, `stop_reason: refusal`, category `cyber`, `bio`, `frontier_llm`, `reasoning_extraction` or
`general_harms`), and this tool feeds it exploit, vulnerability and leaked-secret text. **Tested live on 2026-10-24:**
a realistic OSINT report prompt (open database port, `.git` exposure, an outdated plugin with a CVE id) was declined
by 5.5 with `cyber`, answered by `claude-sonnet-5`, and a milder wording passed on 5.5.

So refusals are handled by the API: `SF_LLM_FALLBACK=default` (the default) sends each request with the server-side
fallback option, and a declined one is re-run on a fallback model inside the same call. It uses the beta endpoint and
works on the Claude API only; set `SF_LLM_FALLBACK=` (empty) to turn it off, or set `SF_LLM_MODEL=claude-sonnet-5` to
skip 5.5 altogether. If a request is declined and the fallback declines too, the call raises "Claude declined the
request (category: ...)".

### Bumping pins

```bash
cd deploy && uv pip compile requirements.in -o requirements.lock --generate-hashes \
  --python-version 3.12 --no-header --exclude-newer <today-14d>T00:00:00Z \
  --exclude-newer-package <pkg>=<day after its fixed release> \
  --override requirements-overrides.txt --allow-unsafe
```

Delete the old lock first (otherwise uv keeps its pins). Re-compile the tools
lock the same way from `requirements-tools.in`. Then `publish.sh` rebuilds and
gates; nothing is pushed on a failure.

## Frontend

**2026-10-25, in progress:** with the backend proven end to end (see "Active
scanner" above), attention has moved to the React GUI (`frontend/`). First
problem: `Settings` mixed the ~124 third-party API keys scan modules need
(Shodan, Censys, VirusTotal, etc.) into one long alphabetical list with every
other module, including ones with nothing to configure at all — and that list
sat right next to a nav item called "API Keys" that was actually something
else entirely: SpiderFoot's own REST API bearer tokens, unrelated to any
module. Two different things sharing one name, in adjacent nav slots.

Fixed so far:
- A new **Data Source Credentials** page (`/credentials`) lists just the
  ~124 credential-bearing modules, searchable, with a configured/not-configured
  status per module. `Settings` no longer shows a module whose only options
  are credentials; a module with both credential and non-credential options
  still shows the latter in Settings, with a link across to Credentials for
  the former.
- The old "API Keys" nav item is renamed **Access Tokens** (own REST API
  tokens — unchanged functionality, just no longer competing for the same
  name as the new page).
- `Settings`'s ~130-entry flat Global Settings list is now grouped by
  subsystem (AI Provider, Embeddings, Reranker, Vector Search, Network,
  Database, Cache & Queue, Object Storage, Elasticsearch, Web & API, Core),
  mirroring the grouping the backend (`spiderfoot/config/app_config.py`)
  already carries internally but never exposed. The AI Provider group in
  particular — `_llm_provider`/`_llm_model`/`_llm_api_key`/etc., the setting
  that controls whether `sf-agents` calls Anthropic, OpenAI or Ollama — used
  to sit anonymously among those 130 keys with no description at all; it now
  has its own labelled, described section.
- Sensitive-value masking (password input, reveal toggle) is now driven by
  one shared classifier (`frontend/src/lib/settingsMeta.ts`) instead of a
  narrower inline regex that missed at least one real case
  (`_socks5pwd`, the SOCKS proxy password, was never masked before).

Found and fixed along the way, unrelated to the rename itself: every
`RequirePermission`-gated page (Access Tokens, SSO Settings) redirected a
genuine admin straight back to the Dashboard on a fresh page load. Root
cause in `frontend/src/lib/auth.ts` — two independent fetches on mount
(`fetchAuthStatus`, `fetchCurrentUser`) each set the one shared `isLoading`
flag to `false` on their own completion; whichever resolved first cleared
it while `user` could still be `null`, so the permission check ran against
no user and bounced. Fixed by tracking each fetch's completion separately
and only clearing `isLoading` once both are done (`authStatusLoaded` /
`userLoaded` in the store). Confirmed reproducible on `/sso-settings`
(untouched by anything else this session) before fixing, and confirmed
fixed on both routes after.

Verified by running the actual dev build against the live local stack (not
just `tsc`/`vitest`) and walking through the pages in the browser: the
credentials module list, search, the configured/not-configured filter,
editing and saving a credential against the real API, the grouped Settings
sidebar, and a cold load of both previously-redirecting admin pages.

**2026-10-25: same review on `Modules.tsx` and `NewScan.tsx`.** Found the
Modules page's Enable/Disable toggle looked functional and wasn't: the
backend keeps "disabled" state in a plain in-memory Python `set` local to
one API worker process (this deployment runs 4), nothing in the scan
execution path reads it, and `NewScan`'s own module picker ignores it
completely — toggling it changed nothing about what a scan actually runs.
Removed rather than wired up (backend work, not today's scope). Also fixed:
a real data leak where the expanded module view fell back to showing an
option's raw value when it had no description — for an undocumented
credential field, that was the literal API key in plain text to any
authenticated user; the three separate, inconsistent credential-detection
regexes across `Modules.tsx`/`NewScan.tsx` are now the one shared classifier
from the Data Source Credentials work; the "Categories" stat was reading
`GET /api/data/module-categories`, which reliably returns an empty list live
despite every module carrying real category data, now derived from the
modules already being fetched instead. And `NewScan`'s hardcoded Quick Scan
module list had 3 of 20 names (`sfp_dnstxt`, `sfp_httpheaders`,
`sfp_geoinfo`) that no longer exist — renamed or merged upstream at some
point, silently shrinking it to 17 modules with nobody noticing — replaced
with their real successors or dropped where redundant. Verified live:
19/19 resolve now, confirmed by actually selecting Quick Scan in the
browser and watching the module count.

**2026-10-25: user feedback after using the merged build — a real backend
bug, not a UI quirk.** Reported as Data Source Credentials "flickering"
between there/not-there after refresh, and Shodan/Censys keys "not
accepting." Root cause: `get_app_config()` (`spiderfoot/api/dependencies.py`)
is a per-process singleton. `SF_API_WORKERS=4` runs four separate
`multiprocessing`-fork processes inside the one `sf-api` container
(confirmed live via `/proc`), each with its own independent copy loaded
from the database once at *that worker's own startup*. A save writes
through to Postgres correctly, but a read served by a different worker
still returns whatever was in memory at its own startup — invisible until
that worker restarts. Which of the 4 serves any given request is
effectively random, so a save looked like it "sometimes" worked, for any
module, not specifically Shodan or Censys. Fixed by overlaying a fresh
database read on top of the in-memory snapshot in `GET /api/data/modules`
and `GET /api/config`, coercing types so a bool/int option doesn't turn
into a string after the round trip through the database's string-only
storage, and building a *new* opts dict per module rather than mutating in
place — the in-memory dict is the same object a running scan reads its
options from, so mutating it in a display-only GET would make that request
a backdoor writer into live scan state. Verified live, not just unit
tests: wrote a credential via the real PATCH endpoint, then read it back
20 times immediately after across whichever of the 4 real worker
processes answered each request — 100% consistent. Same for Censys's
two-field credential.

Also from that feedback: the AI provider setting moved out of Settings
(a group nobody would think to look for) into its own **AI Connections**
page, with one-click presets for Anthropic, OpenAI, Ollama, Mock, and
DeepSeek — DeepSeek isn't a distinct backend provider type, its API is
OpenAI-wire-compatible, so the preset is just `_llm_provider=openai` with
DeepSeek's base URL pre-filled, no backend change needed. GitHub Copilot
is explicitly called out as *not* available as a preset: its API needs
GitHub's own OAuth device-flow sign-in, not a pasted API key, which
nothing in this backend implements — deliberately not added as a dropdown
entry that would just silently fail. Checked the fourth feedback item
(missing geodata in the `rc5-demotestfire-pass1` AI report) against the
scan's actual module list in Postgres: all 27 modules are HTTP/DNS/TLS
tooling, no `sfp_ipinfo` or any geo-IP module was ever in scope for that
deliberately narrow first pass — not a bug, the report is accurately
reflecting what was actually collected.

**2026-10-25, same feedback session — target-type-aware module selection.**
The deeper question behind "the profile issue again": shouldn't the tools
offered depend on what kind of target you're scanning (domain vs. phone
number vs. IP, etc.)? They already structurally can't do anything irrelevant
— every module only fires when it receives an event type it watches, so a
web-crawling tool enabled against a bare phone number just never runs, it
doesn't error — but New Scan's module picker had no way to show that, so it
offered everything regardless of target type with no indication of what
would actually do anything.

Added `GET /api/data/modules/reachable?target=<value>`: detects the
target's type with the same `SpiderFootHelpers.targetTypeFromString()` the
scan engine itself uses, seeds the same root event(s) `scanner.py` would
seed for a real scan, and walks forward through the watches/produces graph
to the full transitive closure of modules that could ever receive a
relevant event. The graph engine for this already existed
(`spiderfoot/plugins/module_resolver.py`, tested, complete) but — like the
cross-worker config bug and the module enable/disable toggle found earlier
this session — was never wired to anything. New Scan's "By Module" tab now
dims unreachable modules with a tooltip explaining why, while leaving them
selectable rather than hard-filtering, since target-type detection can be
ambiguous.

Verified against the real module catalog: a domain target correctly
excludes exactly the handle-based social-media and wallet-address modules
(`sfp_reddit`, `sfp_etherscan`, `sfp_telegram`, etc. — 20 of 305).
Also surfaced something worth knowing rather than quietly shipping around:
the real module graph is far more interconnected than intuition suggests —
`sfp_tool_phoneinfoga` produces `RAW_RIR_DATA`, a "hub" event type huge
numbers of modules watch, so a phone-number target reaches the same 285
modules a domain target does. That's a real, correct chain (phone → RIR
text blob → whatever else parses RIR text), not a bug in the walk; it just
means this mainly catches the clearly-isolated module categories rather
than being a dramatic filter. Doesn't fully explain "why scans take so
long" either, by the same logic — an irrelevant module that never receives
a matching event costs almost nothing sitting idle in this architecture;
scan duration is driven by the genuinely-relevant active/invasive tools
actually running, not idle ones.

**2026-10-28: `rc.7` confirmation run against `demo.testfire.net`** (PR #10
merged, same 27-module scope as the original pass-1 run, for a fair
comparison): `FINISHED`, 5,328 events in ~2h5m vs. pass-1's 5,324 in ~2h0m —
consistent, no regression. Zero recurrence of the five-tool "did not set a
path" errors; the credentials freshness fix held steady (10/10, then
15/15 consistent reads live against the real deployment, not a hotfix
mount this time). Found one more layer of the same bug class, fixed
immediately: `gobuster` got past the path check this time and hit the
*next* blank-with-no-default required option, `wordlist` — never
surfaced before because the path check failed first in every earlier
run, so this one was never reached. Same fix as before: default it to
the same `/tools/wordlists/common.txt` `ffuf` already correctly uses.

**Also found, not fixed — flagged for follow-up, confirmed unrelated to
anything changed recently:** no scan since the original Oct 25 pair
(`rc5-juiceshop`, `rc5-demotestfire-pass1`) has produced any correlation
results, across three different worker container generations (`rc.5`,
`rc.6`, this `rc.7` run) — `scanner.py`'s `runCorrelations()` checks
`tbl_config`'s `__correlationrules__`, which is empty, despite the 97
correlation rule YAML files being present on disk in every one of those
images. Neither the API's `Config` class nor (as far as traced so far)
anything else loads those files into that config key — unlike modules,
which *do* get a filesystem-fallback load when the DB copy is empty.
Likely explanation: whatever populated it for the original pair never
persisted that to the database, so the moment that specific worker
process was replaced the rules were gone for good, with nothing
re-seeding them since. Not touched by anything in PR #9 or #10. Needs a
proper trace of the scan worker's own startup config path (separate
from the API's) to confirm and fix properly — didn't want to guess at
a fix for something this is involved without being sure.

**2026-10-28: correlation-rules gap above, traced and fixed.** The
scanner never has its own config path — `scanner.py` just runs with
whatever flat `global_opts` dict the API process handed it when the
scan was created (`spiderfoot/api/routers/scan.py`'s
`create_scan()` → `config.get_app_config().get_config()`), so the gap
was entirely inside the API's `Config.__init__`
(`spiderfoot/api/dependencies.py`). `__modules__` already had a
filesystem-fallback load for exactly this situation — "DB copy is
empty, so load it from disk instead" — but `__correlationrules__` had
no equivalent, so it stayed permanently `[]` the moment the DB row
(which is never written in the first place; nothing persists
correlation rules to `tbl_config`) came back empty. Added the same
fallback: when the merged config's `__correlationrules__` is falsy,
load every YAML in `correlations/` (respecting
`SF_CORRELATION_RULES_DIR` if set, same env var the existing manual
`/scans/{id}/correlations/run` endpoint already honoured) via
`SpiderFootHelpers.loadCorrelationRulesRaw()`, same pattern as the
modules fallback. Verified live against the real `rc.7` image before
baking it into a build: hotfix-mounted the fixed `dependencies.py`
into `sf-api` only (scanner workers don't need it — they just receive
whatever the API already resolved), confirmed 95 rules now load
in-process, then ran the real `RuleExecutor` against the already-
finished `rc.7` confirmation scan (`257F1C60`) exactly the way
`scanner.py`'s `runCorrelations()` does — went from the 0 it had
before to 38 correlation results (2 HIGH, 18 MEDIUM, 18 INFO), now
persisted in `tbl_scan_correlation_results` for that scan. Hotfix
mount reverted immediately after. 4 new unit tests added in
`test/unit/test_config_api_modernization.py::TestCorrelationRulesFilesystemFallback`
covering: the real directory loads non-empty rules, a DB-persisted
value (if one ever exists) takes precedence over the filesystem, a
missing/misconfigured rules directory degrades to an empty list
instead of raising, and the loaded shape matches what
`runCorrelations()` actually reads it as. Full targeted suite
(`test_config_api_modernization.py`, `test_correlation_wiring.py`,
`test_router_data_modules.py`, `test_scan_service_phase2.py`,
`test_module_pipeline.py` — 232 tests total) passes clean.

## Deploy

Production (Podman, `stack-podman.yml`) and development (Docker,
`stack-docker.yml`) are set up the same way; each file's header has the full
sequence. In short:

```bash
mkdir -p /srv/spiderfoot/{postgres,redis,qdrant,embeddings-cache}
./deploy/bootstrap-spiderfoot-env.sh    # see "Generating the secrets" below
# then set SPIDERFOOT_TAG and ANTHROPIC_API_KEY in the file it wrote, and deploy the stack
```

State is bind-mounted at an absolute `/srv/spiderfoot/<service>` path, not a
relative one and not a named volume, so it is visible and backupable as plain
files. Compose silently drops Podman-only mount flags such as `:U`, so
directory ownership is set on the host (postgres data dir: uid 70).

### Testing against a safe target

`stack-docker.yml` (dev only) has an opt-in `sf-juiceshop` service (OWASP Juice
Shop), a deliberately vulnerable app for exercising the scanner end-to-end
without an authorisation question. `COMPOSE_PROFILES` must include `testing`
to start it; it is never in `stack-podman.yml`. It publishes host port 5002 -
on a host that is not itself sandboxed, bind it to `127.0.0.1` with a local
compose override rather than editing the tracked file.

### Generating the secrets

```bash
./deploy/bootstrap-spiderfoot-env.sh
```

Run it **on the host that runs the stack** (never the build host), once per
deployment. Each deployment gets its own secrets: the development host must
never hold production credentials. It writes
`/srv/spiderfoot/stack-spiderfoot-env.env` (chmod 600) and prints the generated
secrets **once** — copy them into your password manager then. Re-running it is
always safe: it never overwrites or rotates an existing file. It leaves two
things for you: set `SPIDERFOOT_TAG` to an exact published tag, and replace
`ANTHROPIC_API_KEY` (it cannot be generated). Rotating a generated secret later
has consequences, listed in `stack-podman.env.example`.

The script was recovered from this project's earlier history (it had been
deleted and was referenced by documentation but existed nowhere); see its own
changelog.

## Syncing with upstream

Fetch upstream **without tags**, and merge it on a branch:

```bash
git fetch --no-tags https://github.com/poppopjmp/spiderfoot.git master:refs/remotes/upstream-ref/master
git checkout -b sync/upstream-YYYY-MM-DD && git merge upstream-ref/master
```

Expected conflicts are limited to the files this fork deliberately changes
(`README.md`, `requirements.txt`, `docker/Dockerfile.base`, `docker/build.sh`,
and the `docker/compose/*.yml` files); everything under `deploy/` is this
fork's alone. Never `git push --tags` or `git fetch --tags` from upstream into
this fork: upstream's tag names would collide with, and could overwrite, the
fork's own.

## What to keep in mind

- The stacks apply `no-new-privileges`, `cap_drop`, `read_only` and tmpfs
  where the services tolerate it (found by trial — see `stack-podman.yml`'s
  Warnings). `pids_limit`/`mem_limit` are not set yet.
- AI features call Anthropic directly (Claude Sonnet 5.5, see "AI model") (`sf-agents`; `SF_LLM_PROVIDER=anthropic`,
  `ANTHROPIC_API_KEY`). There is no LLM proxy: the LiteLLM gateway was removed
  after its supply-chain breach, and it had only relayed to Anthropic anyway.
- This runs 300+ OSINT modules, including active recon tools that make
  outbound requests to third parties. Only scan targets you are authorised to
  investigate.
- Never commit an `*.env` file, the GHCR token, or any API key. `*.env` is
  gitignored; keep it that way.
