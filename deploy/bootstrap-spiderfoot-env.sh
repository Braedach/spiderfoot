#!/usr/bin/env bash
# =============================================================================
# Script: bootstrap-spiderfoot-env.sh
# Version: 1.3.0
# Created: 2026-08-06
# Updated: 2026-10-24
#
# Summary:
#   Purpose:
#     Generates stack-spiderfoot-env.env once on host.
#     POSTGRES_PASSWORD, SF_JWT_SECRET_KEY and SF_ADMIN_PASSWORD are
#     generated once and never touched again on later runs: Postgres
#     only applies its password at first initdb, so regenerating it
#     later would desync the file from the actual database password;
#     rotating SF_JWT_SECRET_KEY invalidates every session; rotating
#     SF_ADMIN_PASSWORD locks you out of the UI until you find the new
#     one.
#
#     Run it on the host that RUNS the stack (baden for production, claude
#     for development), never on the build host: the build host has no
#     reason to ever see these values. Run it separately on each so the two
#     deployments get DIFFERENT secrets - the development host must never
#     hold production credentials.
#
#     History: lived in Braedach/Code at Dev/spiderfoot-dev/ until it was
#     deleted along with the rest of that directory (commit 18922aa,
#     "Totally seperated development projects", 2026-09-22) and was then
#     referenced by the stack docs but existed nowhere. Recovered from that
#     history into this fork's deploy/ on 2026-10-23.
#
#   Usage:
#     ./deploy/bootstrap-spiderfoot-env.sh
#     SPIDERFOOT_ENV_DIR=/some/dir ./deploy/bootstrap-spiderfoot-env.sh
#       (default /srv/spiderfoot; the override exists so the script can be
#       tested without touching a real deployment)
#     All 3 secrets print clearly to the terminal on first generation,
#     with a SAVE THIS NOW banner - copy them into wherever you keep
#     sensitive local records (password manager, encrypted note, etc.)
#     before they scroll off screen. This is the only run that ever
#     prints them - after this, they're readable straight from the file:
#       cat /srv/spiderfoot/stack-spiderfoot-env.env
#
#   Prerequisites:
#     - openssl available (standard on Debian)
#
#   Warnings:
#     - Re-running this script is always safe but does nothing once the
#       file exists - it will NOT regenerate or reprint the secrets. If
#       you've lost them, read the file directly instead of re-running
#       this
#     - File assumptions: SF_DATABASE_URL and SF_JWT_SECRET_KEY are this
#       file's OWN variable names, not what the app reads directly - the
#       stack yml maps them to SF_POSTGRES_DSN / SF_JWT_SECRET at
#       container-injection time (confirmed from the app's own source
#       during the claude build). Keep that mapping in the yml, don't
#       rename these here to match
#     - SPIDERFOOT_TAG is written BLANK on purpose. The stacks require an exact
#       published tag (see deploy/README.md) and refuse to start without one,
#       so a stale default here could never be right. Set it by hand.
#     - ANTHROPIC_API_KEY is written as CHANGE_ME. It cannot be generated;
#       paste your own. (CHANGE_ME rather than free text so the re-run check
#       below still notices it was never filled in.)
#     - chmod 600 on the generated file - only root can read it directly
#       on baden; the terminal printout is the one deliberate exception,
#       since a human has to get the values out to store them elsewhere
#
# Changelog:
#   1.3.0 (2026-10-24) - No longer generates SF_LLM_API_KEY: it only authenticated agents to the LiteLLM proxy, which is gone.
#                        Existing env files keep the line harmlessly. ANTHROPIC_API_KEY is still set by hand.
#   1.2.0 (2026-10-23) - Recovered into the fork's deploy/ (see Purpose).
#                        No longer hard-codes IMAGE_TAG=6.1.0-g4b53ca68, which
#                        would have written a retired-scheme tag into every
#                        new env file: SPIDERFOOT_TAG is now written blank and
#                        the final banner says to set it. Added
#                        SF_REPORT_MAX_EVENTS_PER_SCAN=2000 (present in the
#                        env example but missing from the generator).
#                        ANTHROPIC_API_KEY placeholder changed to CHANGE_ME.
#                        Added SPIDERFOOT_ENV_DIR override. Secret generation
#                        itself is unchanged.
#   1.1.0 (2026-08-06) - Added SF_LLM_API_KEY generation - shared secret
#                        between sf-litellm (as LITELLM_MASTER_KEY) and
#                        sf-agents (as SF_LLM_API_KEY), authenticating
#                        agents' calls to the litellm proxy. Ollama
#                        itself needs no credential at all - this only
#                        secures the one hop between agents and litellm.
#                        Existing stack-spiderfoot-env.env files from
#                        before this version won't have it - add the
#                        one line by hand rather than deleting and
#                        regenerating the whole file, which would rotate
#                        the other secrets too.
#   1.0.0 (2026-08-06) - Initial version, split out of build-spiderfoot.sh
#                        v1.5.0's env-bootstrap logic now that build and
#                        run are different hosts. All 3 secrets now print
#                        on first generation (previously only
#                        SF_ADMIN_PASSWORD did) - this file is now the
#                        only record outside baden itself, so all three
#                        need to be copied into local records, not just
#                        the login credential.
#
# =============================================================================

set -euo pipefail

ENV_DIR="${SPIDERFOOT_ENV_DIR:-/srv/spiderfoot}"
ENV_FILE="${ENV_DIR}/stack-spiderfoot-env.env"

COL_RESET='\033[0m'; COL_BLUE='\033[0;34m'; COL_GREEN='\033[0;32m'
COL_YELLOW='\033[0;33m'; COL_RED='\033[0;31m'
info()  { echo -e "${COL_BLUE}[INFO]${COL_RESET} $*"; }
warn()  { echo -e "${COL_YELLOW}[WARN]${COL_RESET} $*" >&2; }
error() { echo -e "${COL_RED}[ERROR]${COL_RESET} $*" >&2; exit 1; }
ok()    { echo -e "${COL_GREEN}[OK]${COL_RESET} $*"; }

mkdir -p "$ENV_DIR"

if [[ -f "$ENV_FILE" ]]; then
  if grep -q "CHANGE_ME" "$ENV_FILE" 2>/dev/null; then
    warn "${ENV_FILE} exists but still has CHANGE_ME placeholders - fill these in by hand before deploying."
  else
    ok "${ENV_FILE} already exists - leaving secrets as-is (this script never rotates them)."
    info "Read them any time with: cat ${ENV_FILE}"
  fi
  exit 0
fi

info "${ENV_FILE} not found - generating one with fresh secrets"
PG_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -hex 16)

cat > "$ENV_FILE" << ENVEOF
# =============================================================================
# stack-spiderfoot-env.env
# Generated by bootstrap-spiderfoot-env.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# POSTGRES_PASSWORD, SF_JWT_SECRET_KEY and SF_ADMIN_PASSWORD
# are generated once and never rotated by this script - changing
# POSTGRES_PASSWORD after the database has initialised breaks auth (the
# postgres image only applies it on first initdb), rotating
# SF_JWT_SECRET_KEY invalidates every session, rotating SF_ADMIN_PASSWORD
# locks you out until you find the new one.
# Edit this file by hand if you actually need to change any of them.
# =============================================================================

TZ=Australia/Perth

# --- PostgreSQL ---
POSTGRES_USER=spiderfoot
POSTGRES_PASSWORD=${PG_PASSWORD}
POSTGRES_DB=spiderfoot

# --- Image tag (REQUIRED - set by hand; the stack refuses to start without it) ---
# An exact tag published by deploy/publish.sh, e.g. v6.1.0-bd.1
SPIDERFOOT_TAG=

# --- Core service config ---
SF_DEPLOYMENT_MODE=microservices
SF_DATABASE_URL=postgresql://spiderfoot:${PG_PASSWORD}@sf-postgres:5432/spiderfoot
SF_REDIS_URL=redis://sf-redis:6379
SF_LOG_FORMAT=json

# --- Auth secrets ---
SF_JWT_SECRET_KEY=${JWT_SECRET}
SF_ADMIN_PASSWORD=${ADMIN_PASSWORD}

# --- AI agents ---
# sf-agents calls Claude directly; set your key here by hand.
ANTHROPIC_API_KEY=CHANGE_ME

# --- AI report generation ---
SF_REPORT_MAX_EVENTS_PER_SCAN=2000

# --- Compose profiles enabled on startup ---
COMPOSE_PROFILES=scan
ENVEOF
chmod 600 "$ENV_FILE"
ok "${ENV_FILE} created."

echo ""
echo "  =========================================================="
echo "   SAVE THESE NOW - this is the only time they print. They"
echo "   also live in ${ENV_FILE} on this host if you lose them,"
echo "   but copy them into your own local records now anyway:"
echo ""
echo "     POSTGRES_PASSWORD : ${PG_PASSWORD}"
echo "     SF_JWT_SECRET_KEY : ${JWT_SECRET}"
echo ""
echo "     SpiderFoot admin login:"
echo "       username: admin   (assumed default - not confirmed in logs,"
echo "                          check the UI's login screen if this doesn't work)"
echo "       password: ${ADMIN_PASSWORD}"
echo "  =========================================================="
echo ""
echo "  STILL TO DO BY HAND in ${ENV_FILE}:"
echo "    - SPIDERFOOT_TAG       set to an exact published tag (e.g. v6.1.0-bd.1)"
echo "    - ANTHROPIC_API_KEY    replace CHANGE_ME with your key"
echo ""
