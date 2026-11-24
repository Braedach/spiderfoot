# braedach/spiderfoot

A hardened fork of [poppopjmp/spiderfoot](https://github.com/poppopjmp/spiderfoot) (the microservices SpiderFoot, v6.1.0),
kept public for licence reasons and run internally. For general SpiderFoot use, documentation and issues, go to
upstream.

**Current release candidate: `v6.1.0-bd.1-rc.53`.** Release candidates are built, deployed and tested with live scans
before any public release; a public build takes no new fixes. See the [changelog](CHANGELOG.md) for what each build
changed and [`UPGRADING.md`](UPGRADING.md) before moving between builds.

## What this fork does differently

- **Stays in scope.** Active modules (probes, port scanners, crawlers) are checked against the target's scope before
  they run and again on every web request. Shared CDN edges are recognised by published ranges and by ASN, so a scan
  does not wander onto other people's servers.
- **Finishes scans.** Scans run in worker processes with heartbeats, and a scan whose process dies is marked failed
  instead of staying `RUNNING`. Modules that could hang a scan are bounded.
- **Better intelligence, fewer false positives.** Every module's `setup()` is tested, tools that never worked were
  fixed, and result floods are collapsed.
- **Active testing, authorised targets only.** The Web Application Test and Network Service Test profiles add
  detection-only checks (cross-site scripting, SQL injection, nuclei templates, service checks) and need an "I am
  authorised" statement. Nothing is exploited or extracted.
- **Reproducible, scanned builds.** Pinned base images, hash-locked Python, a Trivy and Grype gate that blocks a push on
  any fixable critical or high finding. Production only pulls published images.

The long version, with the scan-flow diagrams, is in [`docs/FORK-NOTES.md`](docs/FORK-NOTES.md).

## Run it

You need Docker or Podman with Compose. The stack runs nine containers and publishes one port, the web UI on 5001.

```bash
git clone https://github.com/Braedach/spiderfoot.git && cd spiderfoot
git checkout v6.1.0-bd.1-rc.53

sudo mkdir -p /srv/spiderfoot/{postgres,redis,qdrant,embeddings-cache}
sudo chown -R 1000:1000 /srv/spiderfoot/embeddings-cache
./deploy/bootstrap-spiderfoot-env.sh        # writes /srv/spiderfoot/stack-spiderfoot-env.env, prints secrets once
# edit that file: SPIDERFOOT_TAG=v6.1.0-bd.1-rc.53

COMPOSE_PROFILES=scan docker compose --env-file /srv/spiderfoot/stack-spiderfoot-env.env \
  -f deploy/stack-docker.yml up -d
```

Open http://localhost:5001 and log in with the admin password the script printed. Set an AI provider on the
*AI Connections* page if you want AI reports. Details, Podman, upgrades and building your own images:
[`deploy/README.md`](deploy/README.md).

Guides: [CVEs by software version](docs/cve-by-version.md), [scan coverage and saved settings](docs/scan-coverage.md), [AI report, search indexing and scan progress](docs/ai-report.md).

Only scan targets you are authorised to test.

## Licence

MIT, as upstream, except `modules/sfp_tool_sqlmap.py`, which is GPL-2.0-or-later because it runs sqlmap.
