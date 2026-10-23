#!/usr/bin/env bash
# =============================================================================
# Script: deploy/publish.sh
# Version: 1.0.1
# Created: 2026-10-23
#
# Summary:
#   Purpose:
#     Builds this fork's 5 container images from an explicit release tag
#     (never a floating branch) on a dedicated build host - never the host
#     SpiderFoot ends up running on. Pushes them to GHCR and creates a
#     matching GitHub Release on the fork. Modelled on ARTEX's
#     deploy/publish.sh and Design-Reference s24.3; replaces the old
#     untracked /root/build-spiderfoot.sh on davros.
#
#     Images (flat names, linked to this repo by their OCI source label):
#       ghcr.io/braedach/spiderfoot-base
#       ghcr.io/braedach/spiderfoot-api
#       ghcr.io/braedach/spiderfoot-scanner
#       ghcr.io/braedach/spiderfoot-active-scanner
#       ghcr.io/braedach/spiderfoot-frontend
#
#   Tag scheme (fork-owned, never collides with upstream's vX.Y.Z tags):
#       v<upstream base>-bd.<N>            release,   e.g. v6.1.0-bd.1
#       v<upstream base>-bd.<N>-rc.<M>     test build, e.g. v6.1.0-bd.1-rc.2
#     A release tag also moves :latest. An -rc tag NEVER moves :latest, so
#     a branch test build cannot reach a deployment that follows :latest.
#     An -rc tag creates a GitHub *pre-release*; a release tag a normal one.
#
#   Usage:
#     ./deploy/publish.sh v6.1.0-bd.1-rc.1          # build+push a test build
#     ./deploy/publish.sh v6.1.0-bd.1               # build+push a release
#     ./deploy/publish.sh v6.1.0-bd.1 --force       # rebuild even if published
#     ./deploy/publish.sh v6.1.0-bd.1 --check       # report status, do nothing
#     GPU_ACCEL=1 ./deploy/publish.sh <tag>         # base installs
#       fastembed-gpu instead of fastembed (default 0 = CPU). Only useful
#       for a deployment that really has GPU passthrough configured.
#
#   Prerequisites (build host only needs these three - the Python, Node, Go
#   and C toolchains all run inside the Dockerfiles' own build stages):
#     - git, docker, and the gh CLI (github.com/cli/cli)
#     - a classic GitHub PAT, write:packages + repo scope. NOT a fine-grained
#       token - GHCR push does not work reliably with those regardless of the
#       scopes granted. SCOPE WARNING: a classic PAT with `repo` is NOT limited
#       to one repository - it can read and write every repo the account can
#       reach, private ones included. Use a token created only for this, kept
#       only on the build host, and rotate it. See deploy/README.md "Token
#       scope". Prompted for on first run, cached beside the clone at
#       ../.spiderfoot-publish/.ghcr-token (chmod 600, OUTSIDE the repo).
#       Never pass it as an argument or env var.
#     - the tag must already exist on origin (create it on the commit you
#       mean to ship: the tip of the tested branch for -rc, the merged
#       commit for a release).
#     - optional: DOCKER_IO_USERNAME + DOCKER_IO_RAT in the environment for
#       authenticated docker.io pulls (avoids anonymous rate limits).
#
#   Warnings:
#     - Runs `git checkout <tag>` IN THIS CLONE (it builds from the repo it
#       lives in). Use a clone dedicated to publishing, never a working
#       copy you also develop in. Refuses to run with uncommitted changes.
#     - Packages are PRIVATE on first-ever push of a new image name. The 5
#       flat names already exist and are public; a brand-new name would
#       need flipping to Public once in GitHub's package settings.
#     - active-scanner compiles Go and C tools from source: needs roughly
#       30GB free disk and 6GB RAM, and a cache-cold build can run past 20
#       minutes. Build cache is pruned before and after to stop it filling
#       the disk (found the hard way on davros, 2026-08-06).
#     - The 3 patches the old davros script applied at build time (nginx
#       DNS resolver, nginx /api/agents/ timeout, frontend client timeout)
#       are committed in the fork's source now. Nothing is patched here.
#     - The 5 builds mirror docker/build.sh's order and contexts, but are
#       run here so labels, tags and :latest can be controlled. If upstream
#       adds a service to docker/build.sh, add it to SERVICES below too.
#     - This script is the only supported publisher. The inherited GitHub
#       Actions publish workflows (docker.yml, release.yml) should stay
#       disabled in the fork's Actions settings.
#
# Changelog:
#   1.0.1 (2026-10-23) - State dir (incl. the cached GitHub token) moved out of
#     the repo to ../.spiderfoot-publish, with a hard refusal if it is ever
#     inside the clone. Corrected the token-scope wording: a classic PAT cannot
#     be limited to one repo, contrary to what 1.0.0 claimed.
#   1.0.0 (2026-10-23) - Initial version. Replaces build-spiderfoot.sh
#     v3.7.0: explicit tags instead of a tracked branch, fork tag scheme
#     with -rc builds that never move :latest, no build-time source
#     patching, flat image names, OCI labels set to this repo, published
#     digests recorded in the Release.
#
# =============================================================================

set -euo pipefail

# ---- configuration ----------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# State (log, cached GitHub token, digests) lives BESIDE the clone, never inside
# it: the clone is the Docker build context, and this directory holds a token
# that can write to this account's repositories. Nothing in the Dockerfiles
# copies the whole context today (checked 2026-10-23), but one future
# `COPY . .` would bake the token into a PUBLIC image.
STATE_ROOT="${PUBLISH_STATE_ROOT:-$(dirname "$REPO_ROOT")/.spiderfoot-publish}"
case "$(realpath -m "$STATE_ROOT")/" in
  "$(realpath -m "$REPO_ROOT")/"*)
    echo "[ERROR] STATE_ROOT (${STATE_ROOT}) is inside the repo / Docker build context (${REPO_ROOT})." >&2
    echo "[ERROR] It holds the GitHub token; refusing to run. Set PUBLISH_STATE_ROOT outside the clone." >&2
    exit 1 ;;
esac
LOG_FILE="${STATE_ROOT}/publish.log"
GHCR_TOKEN_FILE="${STATE_ROOT}/.ghcr-token"   # chmod 600, outside the repo
STATE_FILE="${STATE_ROOT}/.publish-state"

GHCR_REGISTRY="ghcr.io"
GHCR_NAMESPACE="braedach"
GH_REPO_SLUG="Braedach/spiderfoot"
GPU_ACCEL="${GPU_ACCEL:-0}"

# Order matters: base first, the rest are built FROM it. Mirrors docker/build.sh.
SERVICES=(base api scanner active-scanner frontend)

TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+-bd\.[0-9]+(-rc\.[0-9]+)?$'

# ---- colour helpers ---------------------------------------------------------
COL_RESET='\033[0m'; COL_BLUE='\033[0;34m'; COL_GREEN='\033[0;32m'
COL_YELLOW='\033[0;33m'; COL_RED='\033[0;31m'
info()  { echo -e "${COL_BLUE}[INFO]${COL_RESET} $*"  | tee -a "$LOG_FILE"; }
warn()  { echo -e "${COL_YELLOW}[WARN]${COL_RESET} $*" | tee -a "$LOG_FILE" >&2; }
error() { echo -e "${COL_RED}[ERROR]${COL_RESET} $*"  | tee -a "$LOG_FILE" >&2; }
ok()    { echo -e "${COL_GREEN}[OK]${COL_RESET} $*"   | tee -a "$LOG_FILE"; }

( umask 077; mkdir -p "$STATE_ROOT" )

# ---- args -------------------------------------------------------------------
FORCE=0
CHECK_ONLY=0
TAG=""
for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=1 ;;
    --check)    CHECK_ONLY=1 ;;
    v*)         TAG="$arg" ;;
    *) error "Unknown argument: $arg (expected a tag like v6.1.0-bd.1, --force, or --check)"; exit 1 ;;
  esac
done
if [[ -z "$TAG" ]]; then
  error "Usage: $0 <tag e.g. v6.1.0-bd.1 or v6.1.0-bd.1-rc.1> [--force] [--check]"
  exit 1
fi
if [[ ! "$TAG" =~ $TAG_RE ]]; then
  error "Tag '${TAG}' does not match the fork scheme v<X.Y.Z>-bd.<N>[-rc.<M>] (e.g. v6.1.0-bd.1)."
  error "Bare vX.Y.Z tags are upstream's namespace and are never used here."
  exit 1
fi

IS_RC=0
[[ "$TAG" == *-rc.* ]] && IS_RC=1

# ---- the tag must exist on origin (checked without touching the work tree) ---
if ! git -C "$REPO_ROOT" ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1; then
  error "Tag ${TAG} does not exist on origin. Create and push it on the commit you intend to ship first:"
  error "    git tag -a ${TAG} -m \"...\" <commit> && git push origin ${TAG}"
  exit 1
fi

# ---- already published? -----------------------------------------------------
if [[ -f "$STATE_FILE" ]] && grep -qxF "tag=${TAG}" "$STATE_FILE" 2>/dev/null && [[ "$FORCE" -eq 0 ]]; then
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    info "Check-only: ${TAG} already published by this clone - nothing to do"
  else
    ok "${TAG} already built and published - nothing to do (use --force to rebuild/republish)"
  fi
  exit 0
fi
if [[ "$CHECK_ONLY" -eq 1 ]]; then
  info "Check-only: ${TAG} exists on origin and is not yet published by this clone (rc=${IS_RC})"
  exit 0
fi

# ---- preflight: tools, clean tree ------------------------------------------
for t in git docker gh; do
  command -v "$t" >/dev/null 2>&1 || { error "'${t}' not found on this host."; exit 1; }
done
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]]; then
  error "Uncommitted changes in ${REPO_ROOT}. Use a clean clone dedicated to publishing."
  exit 1
fi

# ---- GHCR + GitHub auth (mandatory) -----------------------------------------
GH_TOKEN_VAL=""
FROM_CACHE=0
if [[ -f "$GHCR_TOKEN_FILE" ]]; then
  GH_TOKEN_VAL=$(cat "$GHCR_TOKEN_FILE")
  FROM_CACHE=1
elif [[ -t 0 ]]; then
  read -srp "GitHub token (classic PAT, write:packages + repo scope): " GH_TOKEN_VAL
  echo
else
  error "No ${GHCR_TOKEN_FILE} and no TTY to prompt (unattended run before first interactive setup?)."
  error "Run once interactively first, or: install -m 600 /dev/null ${GHCR_TOKEN_FILE} and write the token into it."
  exit 1
fi

info "Logging in to ${GHCR_REGISTRY} as ${GHCR_NAMESPACE}..."
LOGIN_OK=0
if echo "${GH_TOKEN_VAL}" | docker login "${GHCR_REGISTRY}" --username "${GHCR_NAMESPACE}" --password-stdin >/dev/null; then
  LOGIN_OK=1
elif [[ "$FROM_CACHE" -eq 1 ]]; then
  warn "${GHCR_REGISTRY} login failed with the cached token - likely expired or revoked."
  rm -f "$GHCR_TOKEN_FILE"
  warn "Removed the stale token file."
  if [[ -t 0 ]]; then
    read -srp "Replacement GitHub token (classic PAT, write:packages + repo scope): " GH_TOKEN_VAL
    echo
    FROM_CACHE=0
    if echo "${GH_TOKEN_VAL}" | docker login "${GHCR_REGISTRY}" --username "${GHCR_NAMESPACE}" --password-stdin >/dev/null; then
      LOGIN_OK=1
    fi
  fi
fi
if [[ "$LOGIN_OK" -ne 1 ]]; then
  error "${GHCR_REGISTRY} login failed - check the token (classic PAT, write:packages + repo)."
  exit 1
fi
ok "${GHCR_REGISTRY} login successful"

if [[ ! -f "$GHCR_TOKEN_FILE" && -t 0 ]]; then
  read -rp "Save for future/repeat runs at ${GHCR_TOKEN_FILE}? [y/N] " save_answer
  if [[ "$save_answer" =~ ^[Yy] ]]; then
    ( umask 077; printf '%s\n' "$GH_TOKEN_VAL" > "$GHCR_TOKEN_FILE" )
    chmod 600 "$GHCR_TOKEN_FILE"
    info "Saved to ${GHCR_TOKEN_FILE} (chmod 600)"
  fi
fi
GH_PAT="$GH_TOKEN_VAL"
unset GH_TOKEN_VAL

if [[ -n "${DOCKER_IO_USERNAME:-}" && -n "${DOCKER_IO_RAT:-}" ]]; then
  if echo "${DOCKER_IO_RAT}" | docker login --username "${DOCKER_IO_USERNAME}" --password-stdin >/dev/null; then
    ok "docker.io login successful"
  else
    warn "docker.io login failed - continuing with anonymous pulls."
  fi
else
  warn "DOCKER_IO_USERNAME/DOCKER_IO_RAT not set - docker.io pulls are anonymously rate-limited."
fi

# ---- check out the requested tag in-place -----------------------------------
git -C "$REPO_ROOT" fetch origin --tags --force >/dev/null
git -C "$REPO_ROOT" checkout --quiet "$TAG"
SHA_FULL=$(git -C "$REPO_ROOT" rev-parse HEAD)
SHA=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
info "Source at ${TAG} (${SHA})"

# ---- build ------------------------------------------------------------------
info "Pruning stale build cache before starting (active-scanner fills it fast)"
docker builder prune -af >>"$LOG_FILE" 2>&1 || true

build_service() {   # $1 = service
  local svc="$1" local_ref="spiderfoot-$1:${TAG}" dockerfile ctx
  local -a extra=(
    --label "org.opencontainers.image.source=https://github.com/${GH_REPO_SLUG}"
    --label "org.opencontainers.image.version=${TAG}"
    --label "org.opencontainers.image.revision=${SHA_FULL}"
    --label "org.opencontainers.image.title=spiderfoot-${svc}"
  )
  case "$svc" in
    base)
      dockerfile="docker/Dockerfile.base"; ctx="$REPO_ROOT"
      extra+=(--build-arg "GPU_ACCEL=${GPU_ACCEL}") ;;
    api|scanner|active-scanner)
      dockerfile="docker/Dockerfile.${svc}"; ctx="$REPO_ROOT"
      extra+=(--build-arg "BASE_IMAGE=spiderfoot-base:${TAG}") ;;
    frontend)
      dockerfile="deploy/docker/Dockerfile.frontend"; ctx="$REPO_ROOT/frontend" ;;
    *) error "Unknown service ${svc}"; exit 1 ;;
  esac
  info "Building ${svc} (${local_ref})..."
  if ! docker build -f "${REPO_ROOT}/${dockerfile}" "${extra[@]}" -t "$local_ref" "$ctx" 2>&1 | tee -a "$LOG_FILE"; then
    error "${svc}: docker build failed (see ${LOG_FILE})"
    exit 1
  fi
  ok "${svc}: built"
}

cd "$REPO_ROOT"
for svc in "${SERVICES[@]}"; do build_service "$svc"; done

# ---- verify what was built, at the lowest reliable layer --------------------
# A new digest is not proof the right source went in (Design-Reference s24.3
# item 7). Check the image's own revision label equals the commit being shipped.
for svc in "${SERVICES[@]}"; do
  built_rev=$(docker image inspect "spiderfoot-${svc}:${TAG}" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')
  if [[ "$built_rev" != "$SHA_FULL" ]]; then
    error "${svc}: revision label '${built_rev}' != ${SHA_FULL} - refusing to push."
    exit 1
  fi
done
ok "All 5 images carry revision ${SHA}"

# ---- push to GHCR: version tag, plus :latest for non-rc only -----------------
DIGEST_FILE="${STATE_ROOT}/images-${TAG}.txt"
: > "$DIGEST_FILE"
PUSHED=()
for svc in "${SERVICES[@]}"; do
  local_ref="spiderfoot-${svc}:${TAG}"
  base_ref="${GHCR_REGISTRY}/${GHCR_NAMESPACE}/spiderfoot-${svc}"
  docker tag "$local_ref" "${base_ref}:${TAG}"
  info "Pushing ${base_ref}:${TAG}..."
  if ! push_out=$(docker push "${base_ref}:${TAG}" 2>&1 | tee -a "$LOG_FILE"); then
    error "${svc}: push failed - check token scope (classic PAT, write:packages) and network."
    exit 1
  fi
  digest=$(echo "$push_out" | grep -oE 'digest: sha256:[0-9a-f]{64}' | tail -1 | cut -d' ' -f2)
  [[ -n "$digest" ]] || { error "${svc}: could not read the pushed digest"; exit 1; }
  echo "${base_ref}:${TAG}@${digest}" >> "$DIGEST_FILE"
  PUSHED+=("${base_ref}:${TAG}")
  if [[ "$IS_RC" -eq 0 ]]; then
    docker tag "$local_ref" "${base_ref}:latest"
    info "Pushing ${base_ref}:latest..."
    docker push "${base_ref}:latest" >/dev/null
    PUSHED+=("${base_ref}:latest")
  fi
done
if [[ "$IS_RC" -eq 1 ]]; then
  ok "Pushed 5 images at ${TAG}; :latest deliberately NOT moved (rc build)"
else
  ok "Pushed 5 images at ${TAG} and moved :latest"
fi

# ---- GitHub Release ---------------------------------------------------------
REL_FLAGS=()
[[ "$IS_RC" -eq 1 ]] && REL_FLAGS+=(--prerelease)
if GH_TOKEN="$GH_PAT" gh release view "$TAG" --repo "$GH_REPO_SLUG" >/dev/null 2>&1; then
  info "Release ${TAG} exists - refreshing its image list"
  GH_TOKEN="$GH_PAT" gh release upload "$TAG" "$DIGEST_FILE#Image digests" --repo "$GH_REPO_SLUG" --clobber
else
  info "Creating GitHub Release ${TAG} on ${GH_REPO_SLUG}..."
  GH_TOKEN="$GH_PAT" gh release create "$TAG" "$DIGEST_FILE#Image digests" \
    --repo "$GH_REPO_SLUG" --title "SpiderFoot ${TAG}" --generate-notes ${REL_FLAGS[@]+"${REL_FLAGS[@]}"}
fi
ok "Release: https://github.com/${GH_REPO_SLUG}/releases/tag/${TAG}"

# ---- record state, clean up local images ------------------------------------
{
  echo "tag=${TAG}"
  echo "sha=${SHA}"
  echo "gpu_accel=${GPU_ACCEL}"
  echo "published=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "---"
} >> "$STATE_FILE"

for svc in "${SERVICES[@]}"; do
  docker rmi "spiderfoot-${svc}:${TAG}" >/dev/null 2>&1 || true
done
for ref in "${PUSHED[@]}"; do docker rmi "$ref" >/dev/null 2>&1 || true; done
docker builder prune -af >/dev/null 2>&1 || true
docker image prune -f >>"$LOG_FILE" 2>&1 || true

ok "Build and publish complete for ${TAG}"
echo ""
info "Published:"
sed 's/^/    /' "$DIGEST_FILE"
echo ""
warn "A brand-new image name would default to PRIVATE on GHCR - flip it to Public once in package settings."
