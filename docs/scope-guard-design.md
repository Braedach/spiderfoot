# Scope guard: design

Status: DESIGN FOR REVIEW (nothing here is implemented yet). Written 2026-11-16 after the rc.39 validation scans.

## Why

A live scan of a single IP address (the full-footprint profile) made TLS connections to 193 hostnames and web requests to
80 hosts that were not the target's. The port scanners stayed on the target, but the scope gate only covers modules
flagged `invasive`, and most modules that connect to a host are not flagged. A code audit of the 297 modules found:

- 13 modules go through the gate (`invasive` flag).
- 23 more clearly contact event hosts and bypass it (`sslcert`, `httpx`, `whatweb`, `wafw00f`, `testsslsh`, `sslscan`,
  `sslyze`, `tlsx`, `subfinder`, `dnsx`, `gau`, `gowitness`, `snallygaster`, `nbtscan`, `onesixtyone`, `massdns`,
  `dnstwist`, `filemeta`, `trufflehog`, `gitleaks`, and others).
- Some modules (`spider`, `cloudfront`) fetch through helper functions, so a code search cannot classify them.
- For name, phone and username targets, `target.matches()` returns True for everything, so even the existing gate lets
  any host through on those scans.
- For an ASN target, `isDirectlyAuthorisedScope()` returns True for every address, and that also disables the CDN check.
  This path has never been exercised live (there is no authorised ASN scope).

## Principles

1. **Intelligence must not shrink.** Passive and vendor modules, and the identity tools, behave exactly as today. The guard
   only restricts *contact with hosts outside the authorised scope*. Every change ships first in log-only mode.
2. **Scope is defined once, per search case**, in one place, and every layer reads it.
3. **Deny by default for anything that contacts a host.** A module that connects to event-derived hosts and has not been
   classified is treated as active, so a new module cannot slip through.
4. **Defence in depth:** dispatch gate, egress check, and a test that fails when a module is unclassified.
5. **Visible:** the scan log and report say what the guard blocked and why.

## Scope per search case

| Target | In scope for ACTIVE contact | Passive lookups |
|---|---|---|
| IP / IPv6 | the address itself, plus names verified to resolve to it now (reverse-DNS name set at scan start) | allowed for any related data |
| Netblock | addresses inside the block; names resolving into it | allowed |
| Domain / hostname | the name, its parents and subdomains; resolved IPs only if not shared (CDN range or proven shared) | allowed |
| ASN | **none by default.** Active contact requires an explicit per-scan authorisation option and a hard address cap | allowed |
| Email, phone, name, username | **none.** No active contact with hosts found along the way. Vendor lookups and the identity tools only | allowed |

Co-hosted sites, passive-DNS names, affiliates and similar-domain results are **data only** until verified.

## Module classes

Each module has one scope class (central table `spiderfoot/scan/scope_policy.py`, reviewed, with a reason per module):

- `vendor`: calls a vendor or public data API with the event data. Not contact with the target. Never blocked.
- `active`: connects to the host in the event (web, TLS, port, DNS probing, scanners). Gated by the scope for the target.
- `identity`: sends a person's identifiers to many sites (`sfp_accounts`, `maigret`, `user-scanner`). Runs only on person
  scans (`person_targets_only`), capped by its own limits. Never blocked on person scans.
- `local`: parses data already collected. Never blocked.

A module that contacts hosts and is in no class fails a unit test (lint), so it must be classified when it is added.

## Layers

1. **Dispatch gate** (`shouldDispatchToModule`): runs for every `active` module (not only `invasive`), checks scope, the
   CDN and shared-edge ranges, and the shared-IP marks.
2. **Egress check** in `fetchUrl`, `fetchBytes`, `safeSocket`, `safeSSLSocket`: the calling module is known from a thread
   context set around `handleEvent`. An `active` module may only reach in-scope hosts; blocked attempts are logged. Covers
   modules the code audit cannot classify. For `vendor` modules this layer is log-only (it learns, never blocks).
3. **Tool launch:** modules that start external tools (30 of them) only receive events that passed layer 1; batch
   modules re-check each host before adding it to a tool's input file.
4. **Event provenance:** events derived from co-hosted, passive-DNS or affiliate sources are tagged data-only.
5. **CDN and shared-edge ranges:** extend `cdn_ranges.py` with CloudFront, GitHub Pages, Imperva and Bunny (published
   lists, fetched with caching and a static fallback), an ASN-based block for providers with no list (Akamai, Sucuri,
   CDN77, DDoS-Guard and similar; numbers verified live before shipping), and a short verified static list of known
   shared platform addresses. Google Cloud and AWS Global Accelerator lists are NOT used (customer VMs and dedicated
   anycast).

## Rollout (so the intelligence side cannot regress)

1. Ship all layers in **log-only** mode: they record what they would block.
2. Compare against the saved baselines of the rc.39 scans (phone, email, name event counts per module). Any passive, vendor
   or identity module whose output changes is a bug in the guard.
3. Switch to enforcing for the IP scan case first, rerun the IP scan, and compare the hosts touched by active modules: they
   must be the IP and its verified names only.
4. Then enforce for the other target types, ASN last and only with synthetic data.

## Tests

- One test per target type (IP, IPv6, netblock, domain, ASN, email, phone, name, username): feed discovered events from
  inside and outside scope and assert which modules receive them. Synthetic data only, no real people, hosts or IPs.
- ASN: assert that active modules receive nothing without the explicit authorisation option, and that with it the hard
  cap applies.
- A lint test that fails when a module with network contact is unclassified.
- A no-regression test per target type: passive, vendor and identity modules receive the same events as before.
- An egress test: an `active` module calling `fetchUrl` for an out-of-scope host is blocked and logged; a `vendor` module
  is not.

## Open questions for the owner

1. For a domain target, should hosts that resolve to a shared IP still be contacted by *hostname* (web request to the
   name, as today), with only the bare-IP scans blocked? (Recommended: yes, as today.)
2. For ASN: is "passive only unless an explicit per-scan authorisation" the right default? (Recommended: yes.)
3. Log-only for how long? (Recommended: one full set of validation scans, then enforce.)
