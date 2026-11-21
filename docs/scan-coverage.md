# Scan coverage: nikto, naabu and saved settings

## nikto and naabu test every host (rc.50)

Before rc.50, nikto tested only the first 20 web servers a scan found and naabu scanned only the first 50 hosts. Whichever
came later were skipped without a word, and *which* ones were skipped depended on the order events arrived, so two scans of
the same domain could test different hosts.

Now:

- `max_targets` is `0` (every host). A per-scan time budget bounds the tools instead: `total_budget` is 7200 s for nikto and
  3600 s for naabu. `0` means no time limit.
- If the budget (or a limit you set) is spent, the scan log names the first host skipped and, when the scan ends, lists
  every host that was not tested. **A scan that did not test a host says so.**
- nikto waits `request_timeout` (10 s) for one answer and spends at most `timeout` (300 s) on one server. Before, it waited
  up to 300 s for a single answer, so one unresponsive server could hold it for minutes.

## Saved settings can override new defaults

A saved copy of the global settings takes priority over a module's built-in default. A deployment that stored the old
`max_targets` values (20 and 50) keeps them after an upgrade, and a new default alone would not change that.

- The shipped profiles (Full Footprint, Tools Only, Web Application Test, Network Service Test, IP Address) **pin** the new
  values, so a scan started from a profile ignores the old saved ones.
- A scan started with your own module list uses what is saved. Reset `max_targets` to `0` for `sfp_tool_nikto` and
  `sfp_tool_naabu` under Settings.
- The same applies to any option a profile pins (for example the arjun settings). If a scan behaves unlike the documented
  default, check the option under Settings, and the scan's own Settings page shows what the scan actually used.
- A setting changed in a running installation may not reach a scan started immediately afterwards. Reload the settings
  (`POST /api/config/reload`) or restart the API if a new value does not appear in the scan's configuration.

## Comparing two scans

Event counts are a poor measure: the same banner can appear many times. Compare **distinct** values (distinct banners,
distinct host:port pairs) and the list of hosts each tool covered. Ports on a CDN's address (Cloudflare, Fastly and
similar) belong to the CDN, so the scope guard stops probing them after 80 and 443; those are not lost results.
