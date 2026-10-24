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
- **Module paths:** the older tool modules need their `*_path` option set per scan
  (e.g. `/tools/testssl.sh/testssl.sh`); tools are on `PATH` otherwise.
- **Testing an image:** run each tool module against a local server with the
  stack's exact container flags (`--read-only`, `--user 1000:1000`,
  `--cap-drop ALL --cap-add NET_RAW`, the tmpfs mounts). That found a dozen
  modules written for old command lines (dalfox, gowitness, gobuster, tlsx,
  arjun, TruffleHog) and the HOME / capability problems above.
- **Accepted, not fixed:** gosu (Go 1.24.6) in every Postgres image and Node
  packages in Qdrant's SBOM file: neither is ours to patch; revisit when the
  maintainers ship. Grype's openssl findings are Debian-backport false positives.

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
- AI features call Anthropic directly (`sf-agents`; `SF_LLM_PROVIDER=anthropic`,
  `ANTHROPIC_API_KEY`). There is no LLM proxy: the LiteLLM gateway was removed
  after its supply-chain breach, and it had only relayed to Anthropic anyway.
- This runs 300+ OSINT modules, including active recon tools that make
  outbound requests to third parties. Only scan targets you are authorised to
  investigate.
- Never commit an `*.env` file, the GHCR token, or any API key. `*.env` is
  gitignored; keep it that way.
