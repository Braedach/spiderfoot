# rc.49 against rc.45: full-footprint scan of one domain

Two scans of the same domain with the same profile, one on rc.45 and one on rc.49. Hostnames and addresses are replaced
with generic names here.

## Summary

Nothing found by rc.45 was lost for a reason tied to a change made in rc.46-49, with one real exception: **nikto tests a
different set of hosts on each scan**. The other differences are explained below or are unproven.

| | rc.45 | rc.49 |
|---|---|---|
| Events | 16,276 | 34,129 |
| Vulnerability findings | 162 | 162 |
| Distinct banners | 96 | 96 |
| Distinct open ports | 193 | 182 |
| Timeouts logged | 27 | 19 |

## What the differences are

| Difference | Cause | Verdict |
|---|---|---|
| Banner and open-port event counts down 18-22% | The same 96 distinct banners exist in both scans. The drop is duplicate events. | Not a loss |
| 17 ports only in rc.45 (53, 80, 8080, 8443 on three names) | Those names resolve to Cloudflare addresses. The ports belong to Cloudflare, not the target. The CDN guard stops after 80 and 443. | Intended |
| Ports of one host on a cloud provider's address | The host's address rotated between scans; the same ports are present on the new address. | Not a loss |
| One port on a private container-network gateway | The scanner's own container network, seen by masscan. | Not a target |
| One host's port 80 as a host-name record | nmap found ports 80, 81 and 443 on that host in both scans; only a duplicate httpx/naabu record differs (port 80 redirects). | Not a loss |
| Three Shodan jQuery CVE lines | Shodan returned them in rc.45 only. Source data, not our code. | Unproven. The CVE-by-version module covers jQuery from banners. |
| One tlsx line and one snallygaster line | A different address, and a tag-manager URL error. | Source variation |
| 24 nikto findings only in rc.45, 32 only in rc.49 | **nikto runs on the first 20 hosts it hears about (`max_targets` 20) and skips the rest.** With 80+ hosts the chosen 20 depend on event arrival order. rc.45 tested one host that rc.49 did not, and the reverse. | **Real gap** |

## Not the network

Timeouts fell, private-address ports match between the scans (apart from the container gateway), and the logs show no
resets or refusals. There is no sign of a reverse proxy or an IDS/IPS blocking the scanner. The gateway's own IPS log
was not read.

## Proposed fix (a release candidate, not a public build)

nikto should pick hosts in a fixed order that favours the scan target's own names before third-party names, report how
many hosts it skipped, and let the web test profile raise `max_targets`. The same arrival-order sampling should be
checked in naabu and the other capped tools.
