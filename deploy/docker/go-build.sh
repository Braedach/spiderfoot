#!/bin/sh
# =============================================================================
# deploy/docker/go-build.sh
# Version: 1.0.1
# Created: 2026-10-23
#
# Summary:
#   Purpose:
#     Build one Go tool from a pinned version with its vulnerable dependencies
#     raised to the floors in $GO_FLOORS. Used only inside the go-builder stage of
#     Dockerfile.active-scanner.
#
#   Why:
#     `go install tool@version` builds a tool with the dependency versions its
#     authors last committed, so every binary carries whatever x/net, x/crypto,
#     compress, pgx ... was current when THEY released. The first scan of this
#     image found 2 critical and 112 high findings, all of them in those embedded
#     dependencies (the Go standard library in nuclei's case). Waiting for each tool
#     to cut a release is not an option for an image that must not carry known
#     fixable vulnerabilities, and some tools (ffuf, gau) have not released in years.
#     Go's minimum-version selection lets a build raise a dependency above what the
#     tool asked for, so that is done here, in a throwaway module that requires the
#     tool.
#
#   Usage:
#     go-build.sh install <package>@<version>   build in a throwaway module
#     go-build.sh raise                         raise floors in the CURRENT module
#                                               (for tools built from a checkout)
#
#   Warnings:
#     - A floor is only ever applied if the module is already in the tool's
#       dependency graph and its current version is LOWER; it never downgrades and
#       never adds a dependency the tool does not use.
#     - The tool's own `replace` directives are ignored in the throwaway module.
#       That is also why a tool whose go.mod has them cannot use `go install
#       pkg@version` at all (gowitness); it is built from a checkout instead.
#     - The binary is not tested against the newer dependencies by the build. The
#       smoke tests in deploy/README.md ("Testing an image") do that.
#
# Changelog:
#   1.0.0 (2026-10-23) - Initial version.
#   1.0.1 (2026-10-23) - go install with -mod=mod: katana failed on missing go.sum entries.
# =============================================================================
set -eu

: "${GO_FLOORS:?GO_FLOORS must list module@version floors}"

raise() {
  for f in $GO_FLOORS; do
    mod="${f%@*}"; want="${f#*@}"
    have=$(go list -m -f '{{.Version}}' "$mod" 2>/dev/null) || continue
    [ -n "$have" ] || continue
    if [ "$(printf '%s\n%s\n' "$have" "$want" | sort -V | head -n1)" = "$have" ] && [ "$have" != "$want" ]; then
      echo "[go-build] raising $mod $have -> $want"
      go get "$f"
    fi
  done
}

case "${1:-}" in
  install)
    target="${2:?usage: go-build.sh install <package>@<version>}"
    pkg="${target%@*}"
    work=$(mktemp -d); cd "$work"
    go mod init sfbuild >/dev/null 2>&1
    go get "$target"
    raise
    # -mod=mod: raising dependencies leaves go.sum without entries for what they pull in
    GOFLAGS="$GOFLAGS -mod=mod" go install -v "$pkg"
    cd /; rm -rf "$work" ;;
  raise)
    raise ;;
  *) echo "usage: go-build.sh install <package>@<version> | raise" >&2; exit 2 ;;
esac
