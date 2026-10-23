#!/usr/bin/env bash
# =============================================================================
# Script: deploy/scan-gate.sh
# Version: 1.0.1
# Created: 2026-10-23
#
# Summary:
#   Purpose:
#     The gate publish.sh runs on every image BEFORE it is pushed. Fails (exit 1)
#     if the image has a CRITICAL or HIGH vulnerability that has a fix available,
#     or a secret that is not on the allowlist. Writes a CycloneDX SBOM next to
#     the results. Two independent scanners run; Trivy decides, Grype is a
#     cross-check whose findings are printed and saved but do not fail the build
#     (their severity and "fixed" data disagree often enough on some packages that
#     gating on both would block builds on scanner noise - see README).
#
#   Usage:
#     deploy/scan-gate.sh <local-image> <name> <output-dir>
#       exit 0  pass          exit 1  findings (build must stop)
#       exit 2  scanner/setup error (also stops the build: no scan, no push)
#
#   Prerequisites: docker. Nothing else - both scanners run in containers.
#
#   Warnings:
#     - The scanner images are pinned by DIGEST and were chosen after the March
#       2026 Trivy supply-chain compromise (GHSA-69fq-xp46-6x23: malicious Trivy
#       v0.69.4-0.69.6 releases and trivy-action tags). A digest is not a tag:
#       it cannot be re-pointed. Versions: Trivy 0.75.0, Grype 0.120.1 (both
#       past every published advisory fix and older than the 14-day cool-down
#       when pinned on 2026-10-23). Bump them deliberately, with the same checks.
#     - WHY TRIVY DECIDES AND GRYPE ONLY CROSS-CHECKS (evidence, 2026-10-23): on the
#       rebuilt base image Trivy found nothing fixable while Grype reported 13
#       fixed critical/high "openssl 3.5.7 binary" findings. That string is Debian's
#       system libcrypto, installed as 3.5.7-1~deb13u3. Debian's security tracker
#       lists every one of those CVEs as fixed in trixie at 3.5.7-1~deb13u2 or
#       ~deb13u3 (DSA-6465-1, DSA-6531-1), so the image is patched: Grype matched
#       the upstream version string inside the binary and ignored Debian's backports.
#       Trivy compares distro package versions, which is the right test for OS
#       libraries. Grype is still worth reading (it finds bundled libraries Trivy
#       can miss) - treat a Grype-only finding as "go and check", not as proof.
#     - Only vulnerabilities WITH a fix fail the gate (--ignore-unfixed): a build
#       cannot fix what has no patch. Unfixed findings are still listed in the
#       saved report, and the right response to one in an unused binary is to
#       remove the binary (see Dockerfile.frontend and curl).
#     - Accepting a specific finding is done in deploy/trivyignore.txt, one ID per
#       line WITH a justification comment. Secrets the scanner is expected to find
#       (public exploit fixtures inside the nuclei templates) are allowlisted by
#       path in deploy/trivy-secret.yaml.
#
# Changelog:
#   1.0.0 (2026-10-23) - Initial version, written after the baseline scan of the
#     images in production found 42 critical / 985 high in active-scanner alone.
# =============================================================================
set -uo pipefail

IMG="${1:?usage: scan-gate.sh <local-image> <name> <output-dir>}"
NAME="${2:?}"; OUT="${3:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TRIVY=ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa
GRYPE=ghcr.io/anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe
TRIVY_CACHE=spiderfoot-trivy-cache
GRYPE_CACHE=spiderfoot-grype-cache

mkdir -p "$OUT"; chmod 777 "$OUT"
TAR="${OUT}/${NAME}.tar"
trap 'rm -f "$TAR"' EXIT

echo "[scan] ${NAME}: exporting ${IMG}"
docker save "$IMG" -o "$TAR" || { echo "[scan] ${NAME}: docker save failed" >&2; exit 2; }

# ---- Trivy: the gate --------------------------------------------------------
rm -f "${OUT}/trivy-${NAME}.json"
docker run --rm -v "${TRIVY_CACHE}:/root/.cache" -v "$OUT":/out -v "$HERE":/cfg:ro "$TRIVY" image \
  --input "/out/${NAME}.tar" --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed \
  --ignorefile /cfg/trivyignore.txt --secret-config /cfg/trivy-secret.yaml \
  --timeout 40m --no-progress --skip-version-check --exit-code 1 \
  --format json -o "/out/trivy-${NAME}.json" > "${OUT}/trivy-${NAME}.log" 2>&1
rc=$?
if [[ ! -s "${OUT}/trivy-${NAME}.json" ]]; then
  echo "[scan] ${NAME}: TRIVY PRODUCED NO REPORT (scanner error, exit ${rc}) - refusing to pass" >&2
  tail -5 "${OUT}/trivy-${NAME}.log" >&2; exit 2
fi

# ---- Grype: cross-check (reported, not gating) ------------------------------
docker run --rm -v "${GRYPE_CACHE}:/cache" -e GRYPE_DB_CACHE_DIR=/cache -v "$OUT":/out "$GRYPE" \
  "docker-archive:/out/${NAME}.tar" --only-fixed -o table --file "/out/grype-${NAME}.txt" \
  > "${OUT}/grype-${NAME}.log" 2>&1
gcount=$(grep -cE ' (Critical|High) ' "${OUT}/grype-${NAME}.txt" 2>/dev/null || true)

# ---- SBOM (needs the DB Trivy just fetched) ---------------------------------
docker run --rm -v "${TRIVY_CACHE}:/root/.cache" -v "$OUT":/out "$TRIVY" image \
  --input "/out/${NAME}.tar" --format cyclonedx --skip-version-check --no-progress \
  -o "/out/sbom-${NAME}.cdx.json" > "${OUT}/sbom-${NAME}.log" 2>&1 \
  || echo "[scan] ${NAME}: SBOM generation failed (non-fatal)" >&2

if [[ $rc -eq 0 ]]; then
  echo "[scan] ${NAME}: PASS - no fixable critical/high, no unallowed secrets (grype cross-check: ${gcount:-0} fixed critical/high)"
  exit 0
fi
echo "[scan] ${NAME}: FAIL - fixable critical/high vulnerabilities and/or unallowed secrets (grype cross-check: ${gcount:-0})" >&2
docker run --rm -v "$OUT":/out "$TRIVY" convert --format table --severity CRITICAL,HIGH "/out/trivy-${NAME}.json" 2>/dev/null | head -60 >&2
echo "[scan] ${NAME}: full report: ${OUT}/trivy-${NAME}.json" >&2
exit 1
