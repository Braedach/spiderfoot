from __future__ import annotations

"""SpiderFoot plug-in module: tool_trufflehog."""

# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_trufflehog
# Purpose:     SpiderFoot plug-in for using the trufflehog tool.
#              Tool: https://github.com/trufflesecurity/trufflehog (v3)
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import os
from subprocess import PIPE, Popen, TimeoutExpired
from urllib.parse import urlparse

from spiderfoot import SpiderFootEvent
from spiderfoot.plugins.async_plugin import SpiderFootAsyncPlugin


class sfp_tool_trufflehog(SpiderFootAsyncPlugin):

    """Searches through git repositories for high entropy strings and secrets, digging deep into commit history."""

    meta = {
        'name': "Tool - TruffleHog",
        'summary': "Searches through git repositories for high entropy strings and secrets, digging deep into commit history.",
        'flags': ["tool", "slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "TruffleHog",
            'description': "TruffleHog searches through git repositories for secrets, "
                "digging deep into commit history and branches. This is effective at "
                "finding secrets accidentally committed.",
            'website': "https://github.com/trufflesecurity/truffleHog",
            'repository': "https://github.com/trufflesecurity/truffleHog",
        },
    }

    opts = {
        'verify': False,
        'allrepos': False,
        'trufflehog_path': ''
    }

    optdescs = {
        'trufflehog_path': "Path to your trufflehog binary (v3). Must be set.",
        'verify': "Let TruffleHog verify each secret it finds by trying it against the issuing service's API? "
                  "OFF by default: verification sends the discovered credential to a third party (GitHub, AWS, Slack...) "
                  "as a live login attempt, which an assessment may not be authorised to do.",
        'allrepos': "Search all code repositories found. By default TruffleHog only searches those linked from the target website."
    }

    results = None
    errorState = False

    def setup(self, sfc: SpiderFoot, userOpts: dict = None) -> None:
        """Set up the module."""
        super().setup(sfc, userOpts or {})
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "Target Website"
    def watchedEvents(self) -> list:
        """Return the list of events this module watches."""
        return ['SOCIAL_MEDIA', 'PUBLIC_CODE_REPO']

    def producedEvents(self) -> list:
        """Return the list of events this module produces."""
        return ['PASSWORD_COMPROMISED']

    def handleEvent(self, event: SpiderFootEvent) -> None:
        """Handle an event received by this module."""
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        url = None

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if not self.opts['trufflehog_path']:
            self.error(
                "You enabled sfp_tool_trufflehog but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['trufflehog_path']
        if self.opts['trufflehog_path'].endswith('/'):
            exe = f"{exe}trufflehog"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if eventName == "SOCIAL_MEDIA":
            try:
                url = eventData.split(": ")[1].replace(
                    "<SFURL>", "").replace("</SFURL>", "")
                hostname = urlparse(url).hostname
                if hostname not in ["github.com", "gitlab.com", "bitbucket.org"]:
                    return
            except Exception as e:
                self.debug("Unable to extract repository URL, skipping.")
                return

        if eventName == "PUBLIC_CODE_REPO" and self.opts['allrepos']:
            try:
                url = eventData.split("\n")[1].replace("URL: ", "")
                hostname = urlparse(url).hostname
                if hostname not in ["github.com", "gitlab.com", "bitbucket.org"]:
                    return
            except Exception as e:
                self.debug("Unable to extract repository URL, skipping.")
                return

        if not url:
            return

        if url in self.results:
            self.debug(f"Skipping {url} as already scanned.")
            return

        self.results[url] = True

        # TruffleHog v3 CLI. (v2 took `--json --regex --entropy=... <url>`; the
        # v2 tool is abandoned and none of those flags exist in v3.)
        args = [exe, 'git', url, '--json', '--no-update']
        if not self.opts['verify']:
            args.append('--no-verification')
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, _ = p.communicate(input=None, timeout=600)
            stdout = out.decode('utf-8', errors='replace')
        except TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            self.debug(f"Timed out waiting for trufflehog to finish on {url}")
            return
        except Exception as e:
            self.error(f"Unable to run trufflehog: {e}")
            return

        if not stdout:
            self.debug(f"trufflehog returned no output for {url}")
            return

        for row in stdout.split("\n"):
            row = row.strip()
            if len(row) == 0:
                continue
            try:
                rowjson = json.loads(row)
            except Exception as e:
                # Do not log the row itself: it may contain the secret in clear text.
                self.error(f"Could not parse a line of trufflehog output as JSON: {e}")
                continue

            if not isinstance(rowjson, dict):
                continue

            # Build the event text from an ALLOWLIST, never the whole row: v3 puts
            # the secret in clear text in Raw, RawV2 and SecretParts (and Redacted
            # is empty for many detectors), so a denylist would leak it into the
            # scan database and logs. The secret is shown masked - enough to
            # identify it in the repository, not enough to use it.
            git = (rowjson.get('SourceMetadata') or {}).get('Data', {}).get('Git', {})
            secret = str(rowjson.get('Raw') or '')
            masked = f"{secret[:4]}{'*' * 8} ({len(secret)} characters)" if secret else "n/a"
            fields = [
                ('Detector', rowjson.get('DetectorName')),
                ('Verified', rowjson.get('Verified')),
                ('Secret', masked),
                ('Repository', git.get('repository')),
                ('File', git.get('file')),
                ('Line', git.get('line')),
                ('Commit', git.get('commit')),
                ('Author', git.get('email')),
                ('Timestamp', git.get('timestamp')),
            ]
            descr = "\n".join(f"{k}: {v}" for k, v in fields if v not in (None, ''))
            evt = SpiderFootEvent('PASSWORD_COMPROMISED',
                                  descr, self.__name__, event)
            self.notifyListeners(evt)

        return

# End of sfp_tool_trufflehog class
