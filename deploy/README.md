# deploy/

How this fork is built, released and run. Everything here is separate from upstream's files, so pulling upstream never
conflicts. The long history and policy detail is in [`REFERENCE.md`](REFERENCE.md).

```
deploy/
  publish.sh                    build the 5 images, scan them, push to GHCR, create the GitHub release (build host only)
  scan-gate.sh                  the Trivy + Grype gate publish.sh runs on every image
  stack-docker.yml              Docker Compose stack (development and general use)
  stack-podman.yml              Podman stack (production here, run with podman-compose)
  stack-*.env.example           environment templates, names only, no secrets
  bootstrap-spiderfoot-env.sh   generates the real env file and its secrets, once per deployment
  docker/                       fork-owned Dockerfiles (base, active-scanner, frontend)
  requirements*.lock            hash-locked Python dependencies
```

Both stacks run the same nine services: `sf-postgres`, `sf-redis`, `sf-qdrant`, `sf-api`, `sf-celery-worker`,
`sf-celery-worker-active` (needs `COMPOSE_PROFILES=scan`), `sf-frontend-ui` (port 5001), `sf-agents` and `sf-tor`.
They only pull images; they never build.

## 1. Run it (pull published images)

Needs Docker with the compose plugin, or Podman with `podman-compose`. About 2 GB of RAM and 10 GB of disk.

```bash
git clone https://github.com/Braedach/spiderfoot.git && cd spiderfoot
git checkout v6.1.0-bd.1-rc.49                      # the stack file must come from the tag you deploy

sudo mkdir -p /srv/spiderfoot/{postgres,redis,qdrant,embeddings-cache}
sudo chown -R 1000:1000 /srv/spiderfoot/embeddings-cache
./deploy/bootstrap-spiderfoot-env.sh                # prints the secrets once: save them in a password manager
sudo nano /srv/spiderfoot/stack-spiderfoot-env.env  # set SPIDERFOOT_TAG=v6.1.0-bd.1-rc.49 (required, no default)

export COMPOSE_PROFILES=scan
docker compose --env-file /srv/spiderfoot/stack-spiderfoot-env.env -f deploy/stack-docker.yml up -d
docker ps --format '{{.Names}} {{.Status}}'         # wait for nine containers marked healthy
```

Open http://localhost:5001 and log in as `admin` with the password the script printed. Put a reverse proxy in front for
anything beyond your own machine. Choose the AI provider and key on the *AI Connections* page; no key lives in the
environment. Podman: use `podman-compose -f deploy/stack-podman.yml` instead (its header lists the extra steps).

**Upgrade:** check out the new tag, change `SPIDERFOOT_TAG`, then `pull` and `up -d`. Do not stop and start: that reuses
the old containers. Read [`UPGRADING.md`](../UPGRADING.md) first when the release notes say *breaking*.

## 2. Build the images yourself

Run from the repository root with the tag checked out. Tag the result as `ghcr.io/braedach/spiderfoot-<service>:<tag>`
and the stack file runs it unchanged. Allow 30 GB of disk, 6 GB of RAM and 20 to 45 minutes (the active scanner
compiles Go and C tools).

```bash
TAG=v6.1.0-bd.1-rc.49
R=ghcr.io/braedach/spiderfoot
docker build -f deploy/docker/Dockerfile.base -t $R-base:$TAG .
docker build -f docker/Dockerfile.api             --build-arg BASE_IMAGE=$R-base:$TAG -t $R-api:$TAG .
docker build -f docker/Dockerfile.scanner         --build-arg BASE_IMAGE=$R-base:$TAG -t $R-scanner:$TAG .
docker build -f deploy/docker/Dockerfile.active-scanner --build-arg BASE_IMAGE=$R-base:$TAG -t $R-active-scanner:$TAG .
docker build -f deploy/docker/Dockerfile.frontend -t $R-frontend:$TAG frontend/
```

`BASE_IMAGE` must name the image you just built, so build `base` first. Then follow section 1, minus the pull.

## 3. Publish to your own registry (`publish.sh`)

`publish.sh` builds the same five images, checks each carries the commit's revision, runs the scan gate (a fixable
critical or high vulnerability or an unallowed secret blocks the push), pushes, and creates a GitHub release. To use it
on your own fork, change `GHCR_NAMESPACE` and `GH_REPO_SLUG` near the top of the script, and the `image:` names in the
stack files.

- **Needs:** `git`, `docker`, the `gh` CLI, a **classic** GitHub token with `write:packages` and `repo` (GHCR pushes
  do not work with fine-grained tokens), and 12 GB free under Docker's root.
- **Token:** read from `/etc/davros/ghcr-token` (root-only, `chmod 600`) or prompted for. Never pass it as an
  argument or commit it. A classic `repo` token reaches every repository you own: make one for this only, with an expiry.
- **Tag:** must be annotated and already pushed. `v<base>-bd.<N>` is a release, `-rc.<M>` a test build; an `-rc` never
  moves `:latest`.

```bash
git checkout main && git pull --ff-only
git tag -a v6.1.0-bd.1-rc.50 -m "rc.50: what changed" && git push origin v6.1.0-bd.1-rc.50
nohup ./deploy/publish.sh v6.1.0-bd.1-rc.50 > build-rc50.log 2>&1 < /dev/null &
tail -f build-rc50.log                              # healthy run ends: Scan gate passed, Pushed 5 images, Release URL
./deploy/publish.sh v6.1.0-bd.1-rc.50 --check       # status only
```

Run it in a login shell on a dedicated build host. If the gate fails, nothing is pushed: fix the cause in a pull
request and cut the **next** rc, never change a published tag. A brand-new image name is created private on GHCR; set it
to public once. Keep the inherited GitHub Actions publish workflows disabled.

## Release process

1. Develop on a branch, open a pull request, merge to `main` when the tests pass.
2. Tag `main` as a release candidate and build it (section 3).
3. Deploy the candidate, test it with live scans and watch the database connection count stay flat.
4. Fixes found go into the next candidate. **A public release takes no new fixes**: it is tagged on the commit of a
   candidate that passed, as `v6.1.0-bd.1`, which also moves `:latest`.

## Housekeeping

- **Secrets:** `bootstrap-spiderfoot-env.sh` never overwrites an existing file. Use different secrets for each
  deployment. Rotating one has consequences, listed in the env example file.
- **Backups:** state is plain files under `/srv/spiderfoot/<service>`. Stop the stack and copy them.
- **Test target:** `stack-docker.yml` has an opt-in OWASP Juice Shop (`COMPOSE_PROFILES=scan,testing`, port 5002).
- **Upstream sync:** `git fetch --no-tags https://github.com/poppopjmp/spiderfoot.git master`, merge on a branch. Never
  fetch or push upstream's tags.
