# AI report, search indexing and scan progress

Added in rc.52. Settings are in [`deploy/REFERENCE.md`](../deploy/REFERENCE.md#ai-report-and-search-indexing).

## The AI report

Press **Generate AI Report** on a scan's AI Report tab. The report is written from the scan's own events and correlations in the database, so it
works on any finished scan without rescanning.

- It runs as a background job. The page shows the steps (reading the scan's events, preparing the context, writing the report, formatting), the time
  spent, and a clear message if it fails. You can leave the page; a refresh picks the job up again.
- It reads a *digest* of the whole scan: exact counts for every event type and module, the target's own findings, related context, correlations
  (highest risk first, with their risk and size), what went wrong during the scan, and what was not tested. When a type has more than 200
  findings, 200 are listed, confirmed-first and spread across hosts, and the report says how many findings each host has. Everything is also in the appendix.
- The digest is limited to 900,000 characters (`SF_REPORT_DIGEST_MAX_CHARS`). The account-confidence list can take at most a fifth of it, so it
  cannot crowd out the findings. What does not fit is counted in the report.
- Expect about three minutes for a scan of 40,000 events. The AI service gives up after ten.
- The model and key are set on the **AI Connections** page. The report sends the digest text to that provider (Ollama keeps it on your network).

## Searching a scan

Finished scans are indexed for search in the background by the AI service: one at a time, at low priority, starting a minute after it starts and
then every two minutes, for scans that finished in the last 14 days. Searching a scan that is not indexed yet (`POST /api/rag/search` with a
`scan_id`) starts its indexing ahead of the queue and answers `202` with `indexed`, `total` and `percent`; try again when it says done.
`GET /api/rag/index/{scan_id}` shows the progress.

## Scan progress

The scan page shows, under the percentage bar, which modules are working now (with their own progress line where they have one, for example "55 of
118 servers tested so far"), how many events are waiting, results a minute, and how long since the last result, with a plain note after ten quiet
minutes. **The bar is not time remaining**: it is the share of modules that have produced a result, so it sits near its top while slow tools and lookups
finish. There is no estimate of the time left; for an event-driven scan there is no honest one.
