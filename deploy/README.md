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
├── litellm-config.yaml         # shared by both stacks
```

Both stacks run the same 9 services and only ever **pull** images. They never
build anything. The development stack mirrors production on purpose: what is
tested there is what runs here.

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
GPU_ACCEL=1 ./deploy/publish.sh <tag>     # fastembed-gpu base (default 0 = CPU)
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

## Deploy

Production (Podman, `stack-podman.yml`) and development (Docker,
`stack-docker.yml`) are set up the same way; each file's header has the full
sequence. In short:

```bash
mkdir -p /srv/spiderfoot/{postgres,redis,litellm,qdrant,embeddings-cache}
cp deploy/litellm-config.yaml /srv/spiderfoot/litellm/config.yaml
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
- This runs 300+ OSINT modules, including active recon tools that make
  outbound requests to third parties. Only scan targets you are authorised to
  investigate.
- Never commit an `*.env` file, the GHCR token, or any API key. `*.env` is
  gitignored; keep it that way.
