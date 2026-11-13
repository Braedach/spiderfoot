# -*- coding: utf-8 -*-
"""Run one scan in its own process: ``python -m spiderfoot.scan.isolated_runner``.

Reads the scan arguments as JSON on stdin. Used when Celery cannot take the
scan, so that the scan never shares a process (and GIL) with an API worker
and survives that worker being restarted.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import sys


def main() -> int:
    payload = json.load(sys.stdin)
    from spiderfoot.observability.logger import logListenerSetup
    from spiderfoot.scan.scanner import startSpiderFootScanner

    queue = mp.Queue()
    logListenerSetup(queue, payload["config"])
    startSpiderFootScanner(
        queue,
        payload["scan_name"],
        payload["scan_id"],
        payload["target"],
        payload["target_type"],
        payload["modules"],
        payload["config"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
