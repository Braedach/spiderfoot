# Target reachability check: plan

Status: PROPOSAL, nothing built. For discussion; decisions are listed at the end.

## Why

On 2026-11-27 a Web Application Test scan of `testphp.vulnweb.com` finished in 6 minutes with 7 results, status `FINISHED`.
The web server did not answer on ports 80 or 443 (from the scan host or from a workstation), while two sibling test sites
did. The scan log said "Unable to SSL-connect" and "No reply from testphp.vulnweb.com, aborting", but nothing told the
person that the target had not been tested. Two shortcomings followed:

1. **A dead target looks like a clean scan.** An active scan that never reached the target ends the same way as one that
   did and found little. A pentester could read "7 results" as "nothing wrong".
2. **An error became a finding.** nikto writes connection errors into its results file, and `sfp_tool_nikto.py` stores any
   line it cannot classify as `VULNERABILITY_GENERAL`; the scan stored "44.228.249.3/: Unable to connect to
   44.228.249.3:80" as a vulnerability. That is a false finding that would reach the AI report.

## What "available for testing" means

Two different questions. Neither is checked automatically today (the second rests on the person's own statement):

- **Reachable:** does the target answer at all from where the scan runs? (This plan.)
- **Permitted:** may it be tested? Today this is the person's own statement (`authorised_to_test`, recorded with the scan).
  That stays as it is; reachability is not permission and must never be used as a substitute for it.

## Design

### When it runs

Only for scans that will contact the target: a profile or module selection that includes an active module
(`scope_policy.ACTIVE_MODULES`) **and** a target that is a host name or an IP address. It is skipped for:

- passive-only selections (full-footprint without the active tools is still passive), because a probe is itself contact with
  the target and a passive scan must make none;
- email, phone, person-name, username and ASN targets (no host to probe);
- netblocks (probing a range is a scan in its own right). A netblock is not probed as a whole; per-host checks (below)
  cover it.

It runs once, at the start of `Scanner.__startScan` after the target aliases are known and before modules are started, so
a dead target costs seconds, not the scan's whole run.

### What it does

1. Resolve the name (A and AAAA), through the scan's own resolver settings. No answer is its own result: `no-dns`.
2. Try a TCP connect to a short fixed port list, in parallel, with a short timeout (3 seconds each, about 5 seconds in
   total): 21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443. A refused connection (RST) counts as
   *alive but closed*; only silence counts as *no answer*. The scan's proxy setting is honoured, so the probe leaves from the
   same place as the modules. It reads nothing and sends nothing beyond the TCP handshake.
3. Classify:

| Result | Meaning |
|---|---|
| `reachable` | at least one port open; the open ports are recorded |
| `closed` | the host answered (RST) but no probed port is open |
| `silent` | resolved, but nothing answered at all (down, filtered, or dropping our address) |
| `no-dns` | the name does not resolve |
| `skipped` | not applicable (passive scan, non-host target, probe switched off) |

### What changes because of the result

- **Always:** one clear line in the scan log (status or warning), the result stored with the scan (a scan configuration
  entry `_target_reachability`, plus the open ports) so it survives, and a field in the progress data so the scan page shows
  it: "Target did not answer on any of 15 ports probed. Active tests did not run." It also appears in the scan summary
  and in the AI report's "Coverage and limitations" section, so a report never reads as "tested, nothing found".
- **`silent`, `no-dns`:** the active modules are not started. Their results would be errors, not findings. The passive
  modules still run (DNS, certificate logs, search engines, whois), because they do not need the host to be up. The scan
  ends `FINISHED` with the unreachable flag set, not `ERROR`, because the scan did what it could.
- **`closed`, or `reachable` on other ports only:** a warning; web modules that need 80 or 443 are skipped with the reason
  ("no web port open"), network-service modules still run on the ports that are open.
- **A switch:** `_reachability_gate` = `enforce` (default for active profiles), `warn` (record and show, but run everything),
  `off`. A person who knows the host drops probes from the scan host can set `warn` for that scan.

### Per host, inside the scan

The same idea applies to hosts a scan discovers, not just the seed. nikto, nuclei, naabu and katana already work host by
host; each should skip a host that has not answered a short connect, say so in its progress line (the "skipped" list they
already keep), and not treat the error text as a result. This is the smaller second step.

### The nikto fix (separate, small)

Ignore nikto output lines that are errors rather than findings ("Unable to connect", "No reply", "Connection refused",
timeouts, "ERROR:"), count them as a failed run for that host, and report them in the module's summary. A test with the
exact text from this scan.

## Where it goes in the code

- A new `spiderfoot/scan/reachability.py` (the probe and classification, pure functions plus a small socket helper, so it
  can be unit-tested with local sockets).
- `Scanner.__startScan` calls it once and removes the active modules from the module list for the cases above (the scope
  policy already knows which are active).
- The result is written to the scan configuration and the progress hash; `scan_progress.py` and `ScanActivity.tsx` show it;
  `report_digest.py` adds it to "Coverage and limitations".
- Tests: the probe against local listening, closed and filtered sockets; the gate by profile, target type and mode; the
  nikto error lines; the report digest line.

## What it cannot do

- **A firewall that drops only our scan host** looks like a dead host, so `silent` says "did not answer from here", not "is
  down". The wording must not claim more than we know.
- **A host that answers only on an unusual port** is classed `closed` until the port list is widened; `warn` mode covers it.
- **A host that is up but rate-limits or blocks mid-scan** is outside a one-off check at the start; that is the per-host and
  "quiet scan" warnings' job.
- **It is not an authorisation check.**

## Decisions needed

1. **Gate or warn by default for active profiles.** Recommendation: enforce (skip active modules when `silent` or `no-dns`),
   with `warn` per scan. The alternative is to warn only.
2. **Should a `silent` result end the scan `FINISHED` with a flag, or with a distinct status** (for example `FINISHED-NO-TARGET`)?
   Recommendation: a flag, so existing counts and filters keep working, and the page shows it prominently.
3. **Port list.** The 15 ports above, or only web ports for web profiles? Recommendation: the fixed list for every active
   profile; it is cheap and the result is also useful in the report.
4. **Per host checks now or later.** Recommendation: seed target and the nikto fix first (one release candidate), per-host
   skips in the next.
