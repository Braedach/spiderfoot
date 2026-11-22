"""SpiderFoot module: look up known CVEs for the software versions a scan finds.

The scan sees a version in a banner ("nginx/1.18.0") or is told one ("grimmory 3.5.0" in the declared_software option, for
applications that hide their version from outsiders). The module asks live vulnerability databases which published
CVEs affect that exact version. The database does the version matching (NVD understands "affected up to 3.5.0"
ranges; OSV does the same for the package it is given); a language model is not involved, because its knowledge
stops at its training date and a new CVE is the case this module exists for.

A match means the *version* is listed as affected. It does not prove the flaw can be exploited here: vendors
backport fixes without changing the version number, and some flaws need a setting. Findings say so.

Event flow:
  IN:  WEBSERVER_BANNER, WEBSERVER_TECHNOLOGY, SOFTWARE_USED, INTERNET_NAME (to apply declared_software)
  OUT: VULNERABILITY_CVE_CRITICAL, VULNERABILITY_CVE_HIGH, VULNERABILITY_CVE_MEDIUM, VULNERABILITY_CVE_LOW,
       VULNERABILITY_GENERAL, RAW_RIR_DATA
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import quote

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

NVD = "https://services.nvd.nist.gov/rest/json"
OSV = "https://api.osv.dev/v1/query"

# product/1.2.3, product 1.2.3, product-1.2.3, "Product v1.2.3"; the version must look like a version (digit first)
_PRODUCT_VERSION = re.compile(r"(?i)\b([a-z][a-z0-9_.+-]{1,40}?)(?:/|\s+v?|-v?)(\d+(?:\.\d+){1,3}[a-z0-9._-]{0,12})")
_NOT_PRODUCTS = {"http", "https", "tls", "ssl", "tlsv", "sslv", "version", "build", "port", "ip", "ipv", "mozilla", "applewebkit",
                 "chrome", "safari", "khtml", "gecko", "like", "linux", "windows", "ubuntu", "debian", "centos", "unix"}


# Names banners use that differ from NVD's product name (vendor, product)
PRODUCT_ALIASES = {
    "apache": ("apache", "http_server"), "httpd": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"), "microsoft-iis": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"), "mysql": ("oracle", "mysql"), "tomcat": ("apache", "tomcat"),
    "proftpd": ("proftpd", "proftpd"), "exim": ("exim", "exim"), "postfix": ("postfix", "postfix"),
}


def parse_software(text: str) -> list[tuple[str, str]]:
    """Return (product, version) pairs found in a banner or technology string."""
    found = []
    for product, version in _PRODUCT_VERSION.findall(text or ""):
        product = product.lower().strip("-_.+")
        version = version.rstrip("._-")
        if product and product not in _NOT_PRODUCTS and (product, version) not in found:
            found.append((product, version))
    return found


def parse_declared(text: str) -> list[dict]:
    """Read the declared_software option: one `host | product | version | vendor | purl` per line (vendor and purl optional).

    Lines starting with # are comments. A line missing host, product or version is ignored.
    """
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")] + [""] * 5
        host, product, version, vendor, purl = (p for p in parts[:5])
        if host and product and version:
            rows.append({"host": host.lower(), "product": product.lower(), "version": version,
                         "vendor": vendor.lower(), "purl": purl})
    return rows


def cvss_rating(score) -> str | None:
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score >= 0 else None


def read_nvd_cve(item: dict) -> dict:
    """Reduce one NVD vulnerability record to id, score, summary, fixed-in hints and whether it is known exploited."""
    cve = item.get("cve", item)
    score = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = (cve.get("metrics") or {}).get(key) or []
        if rows:
            score = (rows[0].get("cvssData") or {}).get("baseScore")
            if score is not None:
                break
    summary = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"id": cve.get("id", ""), "score": score, "summary": " ".join(summary.split())[:300],
            "kev": bool(cve.get("cisaExploitAdd")), "source": "NVD"}


def read_osv(vuln: dict) -> dict:
    """Reduce one OSV record. The CVE id is taken from the aliases when the record has its own (GHSA-...) id."""
    ids = [vuln.get("id", "")] + list(vuln.get("aliases") or [])
    cve_id = next((i for i in ids if i.startswith("CVE-")), vuln.get("id", ""))
    score = None
    rating = (vuln.get("database_specific") or {}).get("severity")
    fixed = []
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return {"id": cve_id, "score": score, "rating": str(rating).upper() if rating else None,
            "summary": " ".join((vuln.get("summary") or vuln.get("details") or "").split())[:300],
            "fixed": sorted(set(fixed)), "kev": False, "source": "OSV"}


def _version_key(version: str) -> tuple:
    return tuple(int(n) for n in re.findall(r"\d+", version.split("-")[0])[:6])


def version_matches(version: str, spec: str) -> bool:
    """True when the version satisfies a GitHub advisory range such as '>= 1.0.0, < 2.1.0' or '<= 3.4.1'."""
    have = _version_key(version)
    if not have or not spec:
        return False
    for clause in spec.split(","):
        m = re.match(r"\s*(<=|>=|<|>|=)?\s*v?(\d[\w.]*)\s*$", clause)
        if not m:
            return False
        op, want = m.group(1) or "=", _version_key(m.group(2))
        width = max(len(have), len(want))
        a, b = have + (0,) * (width - len(have)), want + (0,) * (width - len(want))
        if not {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "=": a == b}[op]:
            return False
    return True


def read_github_advisories(rows: list, product: str, version: str) -> list[dict]:
    """Advisories from a project's own GitHub security page that list this product and version as affected.

    Only entries for the product itself count (a project's advisories also name its libraries and its container image).
    """
    out = []
    for adv in rows or []:
        for vuln in adv.get("vulnerabilities") or []:
            name = ((vuln.get("package") or {}).get("name") or "").lower()
            if name != product and not name.endswith("/" + product):
                continue
            if version_matches(version, vuln.get("vulnerable_version_range") or ""):
                out.append({"id": adv.get("cve_id") or adv.get("ghsa_id", ""), "score": (adv.get("cvss") or {}).get("score"),
                            "rating": (adv.get("severity") or "").upper() or None,
                            "summary": " ".join((adv.get("summary") or "").split())[:300],
                            "fixed": [vuln["patched_versions"]] if vuln.get("patched_versions") else [],
                            "kev": False, "source": "GitHub advisories"})
                break
    return out


class sfp_cve_by_version(SpiderFootPlugin):
    """Known CVEs for the software versions a scan finds or is told about."""

    meta = {
        "name": "CVEs by Software Version",
        "summary": "Look up published CVEs (NVD, OSV) for software versions seen in banners or declared by the owner.",
        "flags": ["slow", "apikey"],
        "useCases": ["Investigate", "Footprint", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://nvd.nist.gov/",
            "model": "FREE_NOAUTH_LIMITED",
            "references": ["https://nvd.nist.gov/developers/vulnerabilities", "https://google.github.io/osv.dev/api/"],
            "description": "NIST National Vulnerability Database, OSV and projects' own GitHub security advisories, queried by software version.",
            "apiKeyInstructions": [
                "The key is optional: without it NVD allows 5 requests per 30 seconds",
                "Visit https://nvd.nist.gov/developers/request-an-api-key",
                "Enter your email address and request a key",
                "Paste the key from the confirmation email into the NVD API key option",
            ],
        },
    }

    opts = {
        "declared_software": "",
        "nvd_api_key": "",
        "use_nvd": True,
        "use_osv": True,
        "use_github": True,
        "github_token": "",
        "github_cache_hours": 12,
        "max_lookups": 40,
        "max_per_product": 25,
    }
    optdescs = {
        "declared_software": "Software the scan cannot see from outside, one per line: host | product | version | vendor (optional) | purl (optional). "
                             "Example: grimmory.example.org | grimmory | 3.5.0 | | github:grimmory-tools/grimmory. "
                             "Use the host the scan targets. The last column is either a purl (pkg:maven/...) for OSV, or github:owner/repo to read the project's own published advisories, for open-source apps that NVD does not list.",
        "nvd_api_key": "Free NVD API key (nvd.nist.gov/developers/request-an-api-key). Without one NVD allows 5 requests per 30 seconds.",
        "use_nvd": "Query NVD.",
        "use_osv": "Query OSV (needs a purl in declared_software).",
        "use_github": "Query the project's own GitHub security advisories (needs github:owner/repo in declared_software). "
                      "Many projects publish an advisory there before NVD or OSV list it.",
        "github_token": "Optional GitHub token (no scopes needed). Without one GitHub allows 60 requests per hour per address.",
        "github_cache_hours": "Keep each project's advisories this many hours and reuse them for every scan, so one fetch serves many "
                              "scans (0 = always ask GitHub). After this long the list is re-checked with a conditional request. "
                              "If GitHub refuses (rate limit), the last copy is used and the log says so.",
        "max_lookups": "Most software versions looked up in one scan.",
        "max_per_product": "Most CVEs reported per software version (highest score first).",
    }

    results = None

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self._lookups = 0
        self._last_nvd = 0.0
        self._warned = set()
        self._declared = None
        for opt in list(userOpts or {}):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY", "SOFTWARE_USED", "INTERNET_NAME"]

    def producedEvents(self):
        return ["VULNERABILITY_CVE_CRITICAL", "VULNERABILITY_CVE_HIGH", "VULNERABILITY_CVE_MEDIUM",
                "VULNERABILITY_CVE_LOW", "VULNERABILITY_GENERAL", "RAW_RIR_DATA"]

    # -- network ---------------------------------------------------------------------------------------------------

    def _get_json(self, url: str, headers: dict | None = None, post: dict | None = None):
        res = self.sf.fetchUrl(url, timeout=self.opts.get("_fetchtimeout", 30), useragent=self.opts.get("_useragent", "SpiderFoot"),
                               headers=headers, postData=json.dumps(post) if post is not None else None)
        if not res or res.get("code") != "200" or not res.get("content"):
            code = (res or {}).get("code")
            base = url.split("?")[0]
            if code in ("403", "429") and base not in self._warned:
                self._warned.add(base)
                self.error(f"{base} refused the request (HTTP {code}): rate limited. Add the API key or token in this module's settings; "
                           "findings from this source are missing from this scan.")
            return None
        try:
            return json.loads(res["content"]) if isinstance(res["content"], str) else res["content"]
        except ValueError:
            return None

    def _nvd(self, path: str):
        key = self.opts.get("nvd_api_key", "")
        gap = 0.7 if key else 6.5      # NVD allows 50 requests per 30 s with a key, 5 without
        wait = self._last_nvd + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last_nvd = time.monotonic()
        return self._get_json(f"{NVD}/{path}", headers={"apiKey": key} if key else None)

    def nvd_cves(self, vendor: str, product: str, version: str) -> list[dict]:
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        data = self._nvd(f"cves/2.0?virtualMatchString={quote(cpe, safe=':*')}&resultsPerPage=200")
        return [read_nvd_cve(v) for v in (data or {}).get("vulnerabilities", [])]

    def osv_cves(self, purl: str, version: str) -> list[dict]:
        data = self._get_json(OSV, post={"version": version, "package": {"purl": purl.split("@")[0]}})
        return [read_osv(v) for v in (data or {}).get("vulns", [])]

    def github_advisories(self, repo: str) -> list:
        """The project's published advisories: from the local copy while it is fresh, else asked for again.

        One fetch serves every scan for ``github_cache_hours``. After that the list is re-checked with the ETag from the last
        fetch (a 304 reply keeps the copy). If GitHub refuses, the last copy is used rather than losing the findings.
        """
        label = f"sf_cve_by_version_github:{repo}"
        hours = float(self.opts.get("github_cache_hours", 12) or 0)
        saved = None
        if hours:
            try:
                saved = json.loads(self.sf.cacheGet(label, 0) or "null")
            except (ValueError, TypeError):
                saved = None
            if not (isinstance(saved, dict) and isinstance(saved.get("rows"), list)):
                saved = None
            if saved and time.time() - float(saved.get("fetched", 0)) < hours * 3600:
                return saved["rows"]
        key = self.opts.get("github_token", "")
        headers = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {key}"} if key else {})}
        if saved and saved.get("etag"):
            headers["If-None-Match"] = saved["etag"]
        url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100"
        res = self.sf.fetchUrl(url, timeout=self.opts.get("_fetchtimeout", 30), useragent=self.opts.get("_useragent", "SpiderFoot"),
                               headers=headers)
        code = (res or {}).get("code")
        rows = None
        etag = ""
        if code == "304" and saved:
            rows, etag = saved["rows"], saved.get("etag", "")
        elif code == "200" and (res or {}).get("content"):
            try:
                body = json.loads(res["content"]) if isinstance(res["content"], str) else res["content"]
            except ValueError:
                body = None
            if isinstance(body, list):
                rows = body
                etag = next((v for k, v in (res.get("headers") or {}).items() if str(k).lower() == "etag"), "") or ""
        if rows is None:
            if saved:
                if url not in self._warned:
                    self._warned.add(url)
                    self.error(f"GitHub did not answer for {repo} (HTTP {code}); using the copy of its advisories fetched "
                               f"{int((time.time() - float(saved.get('fetched', 0))) / 3600)} hours ago.")
                return saved["rows"]
            if code in ("403", "429") and url.split("?")[0] not in self._warned:
                self._warned.add(url.split("?")[0])
                self.error(f"{url.split('?')[0]} refused the request (HTTP {code}): rate limited. Add the API key or token in this "
                           "module's settings; findings from this source are missing from this scan.")
            return []
        if hours:
            try:
                self.sf.cachePut(label, json.dumps({"fetched": time.time(), "etag": etag, "rows": rows}))
            except (OSError, TypeError, ValueError):
                pass
        return rows

    def github_cves(self, repo: str, product: str, version: str) -> list[dict]:
        return read_github_advisories(self.github_advisories(repo), product, version)

    # -- events ----------------------------------------------------------------------------------------------------

    def handleEvent(self, event):
        if self.errorState:
            return
        if event.eventType == "INTERNET_NAME":
            if self._declared is None:
                self._declared = parse_declared(self.opts.get("declared_software", ""))
            for row in self._declared:
                if row["host"] == event.data.lower():
                    self._check(event, row["product"], row["version"], row["vendor"], row["purl"], declared=True)
            return
        for product, version in parse_software(event.data):
            self._check(event, product, version, "", "", declared=False)

    def _check(self, event, product, version, vendor, purl, declared):
        key = f"{product}:{version}:{event.data.lower()}" if declared else f"{product}:{version}"
        if key in self.results:
            return
        self.results[key] = True
        if self._lookups >= self.opts["max_lookups"]:
            return
        self._lookups += 1

        found = {}
        if self.opts["use_nvd"]:
            v, prod = (vendor, product) if vendor else PRODUCT_ALIASES.get(product, ("*", product))
            for cve in self.nvd_cves(v, prod, version):     # vendor "*": NVD files nginx under igor_sysoev and f5, so any vendor
                found.setdefault(cve["id"], cve)
        if purl.startswith("github:"):
            if self.opts["use_github"]:
                for cve in self.github_cves(purl[7:], product, version):
                    found.setdefault(cve["id"], cve)
        elif self.opts["use_osv"] and purl:
            for cve in self.osv_cves(purl, version):
                found.setdefault(cve["id"], cve)
        if not found:
            return

        ranked = sorted(found.values(), key=lambda c: (not c["kev"], -(float(c["score"]) if c["score"] is not None else -1)))
        origin = "declared by the owner" if declared else f"seen in '{event.data[:80]}'"
        for cve in ranked[: self.opts["max_per_product"]]:
            rating = cvss_rating(cve["score"]) or cve.get("rating")
            etype = f"VULNERABILITY_CVE_{rating}" if rating in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "VULNERABILITY_GENERAL"
            lines = [f"{cve['id']} (score {cve['score'] if cve['score'] is not None else 'unknown'}"
                     f"{', known to be exploited' if cve['kev'] else ''}) may affect {product} {version} ({origin}).",
                     cve["summary"]]
            if cve.get("fixed"):
                lines.append("Fixed in: " + ", ".join(cve["fixed"]))
            lines.append(f"Source: {cve['source']}. The database lists this version as affected. Check the vendor notice: fixes are "
                         "often backported without a version change, and some flaws need a particular setting.")
            self.notifyListeners(SpiderFootEvent(etype, "\n".join(lines), self.__class__.__name__, event))
        total = len(ranked)
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", json.dumps({"product": product, "version": version, "cves": total}),
                                             self.__class__.__name__, event))
