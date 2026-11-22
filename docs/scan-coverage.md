# Scan coverage: nikto, nuclei, naabu and saved settings

## The web and port tools test every host (rc.50, completed in rc.51)

Before rc.50, nikto tested only the first 20 web servers a scan found and naabu scanned only the first 50 hosts. nuclei had
the same kind of limit (20 targets) until rc.51. Whichever came later were skipped without a word, and *which* ones were
skipped depended on the order events arrived, so two scans of the same domain could test different hosts.

Now:

- `max_targets` is `0` (every host) for nikto, nuclei and naabu.
- Each run is bounded on its own: nikto by `timeout` (300 s per server, with `request_timeout` of 10 s for a single answer),
  nuclei by `max_scan_duration`. A scan-wide time budget is **off** for nikto and nuclei (`total_budget` 0) and 3600 s for
  naabu; set one if you want a hard cap. With a budget set, runs are shortened past 70% of it and nothing new starts past
  150%, so later hosts still get tested.
- **A scan that did not test a host says so.** Every skipped host is logged when it is skipped, and the list is repeated when
  the scan ends.
- nikto treats a plain `http://` address on a TLS port (443, 8443 and similar) as the https server, and tests each server
  once. Before, those addresses waited out the full 300 s for nothing.
- The long profiles (Tools Only, Web Application Test, Network Service Test) now allow up to 240 minutes, so a scan of a site
  with many web servers is not stopped while the tools are still working. A scan ends when its work does.

## Saved settings and new defaults

The Settings screen saves every module option it shows, so a value that was only ever a default gets stored and used from then
on, even after a newer release changes the default.

- **Retired defaults are ignored (rc.51).** Saved values that equal a default a release has replaced (nikto and nuclei
  `max_targets` 20, naabu 50, nikto `total_budget` 7200, the old arjun settings) no longer apply: the current default does, for
  every scan, including one with your own module list. Nothing needs resetting. Any other value you chose is kept. (If you chose
  exactly one of the retired values on purpose, it is replaced too; pick a nearby value, such as 21, to keep a limit.)
- The shipped profiles also **pin** the coverage settings and the nuclei excluded tags (`dos,fuzz,intrusive`), so a scan
  started from a profile ignores a saved edit to them.
- A setting changed in a running installation now reaches the next scan: starting a scan reads the settings fresh.
- The scan's own Settings page shows what the scan actually used, which is the quickest check when a scan behaves unlike the
  documented default.

## Known CVEs for a project's own advisories

`sfp_cve_by_version` keeps each project's published GitHub advisories for 12 hours (`github_cache_hours`), so many scans share
one request and a rate-limited address keeps its findings. See [CVEs by software version](cve-by-version.md).

## Comparing two scans

Event counts are a poor measure: the same banner can appear many times. Compare **distinct** values (distinct banners,
distinct host:port pairs) and the list of hosts each tool covered. Ports on a CDN's address (Cloudflare, Fastly and
similar) belong to the CDN, so the scope guard stops probing them after 80 and 443; those are not lost results.
