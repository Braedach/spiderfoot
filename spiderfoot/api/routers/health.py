"""
Health Check API Router for SpiderFoot.

Exposes Kubernetes-compatible health probes and a comprehensive
service status dashboard through FastAPI endpoints.  Wires together
subsystem-specific checks (PostgreSQL, Redis, Celery, Vector.dev,
MinIO, app config) and Prometheus-compatible metrics.

Endpoints:
  GET /health           - Overall health (liveness + readiness)
  GET /health/live      - Liveness probe (is process alive?)
  GET /health/ready     - Readiness probe (can handle traffic?)
  GET /health/startup   - Startup probe (initialization done?)
  GET /health/dashboard - Full subsystem status overview
  GET /health/{name}    - Individual component check
  GET /metrics          - Prometheus exposition format
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import threading
import time
from typing import Any

log = logging.getLogger("spiderfoot.api.health")

try:
    from fastapi import APIRouter, HTTPException, Response
    from fastapi.responses import PlainTextResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


# -----------------------------------------------------------------------
# Health check providers — lazy imports to avoid hard dependencies
# -----------------------------------------------------------------------


def _check_vector() -> dict[str, Any]:
    """Vector.dev log pipeline health (not the Qdrant vector database: see _check_qdrant)."""
    # The Vector log shipper is not part of this fork's stack. Probing a default host name for it made the
    # dashboard show "vector: down" on a healthy installation, so it is checked only when its URL is set.
    api_url = os.environ.get("VECTOR_API_URL", "").strip()
    if not api_url:
        return {"status": "unknown", "message": "Not configured (the Vector log pipeline is not deployed)"}
    try:
        from spiderfoot.observability.vector_bootstrap import VectorBootstrap, VectorBootstrapConfig
        # (SF_VECTOR_HTTP_PORT=8686 is the event-ingestion HTTP source port, not the management API)
        cfg = VectorBootstrapConfig(
            vector_api_url=api_url,
            vector_graphql_url=f"{api_url}/graphql",
        )
        vb = VectorBootstrap(config=cfg)
        health = vb.check_health()
        if health.reachable:
            return {
                "status": "up",
                "version": health.version,
                "uptime_seconds": health.uptime_seconds,
            }
        return {
            "status": "down",
            "message": health.error or "Unreachable",
        }
    except ImportError:
        return {"status": "unknown", "message": "VectorBootstrap not available"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_report_storage() -> dict[str, Any]:
    """Report storage backend health."""
    try:
        from spiderfoot.reporting.report_storage import ReportStore, StoreConfig
        store = ReportStore(StoreConfig())
        # Quick count to verify backend
        count = store.count()
        return {
            "status": "up",
            "backend": store.config.backend.value,
            "report_count": count,
        }
    except ImportError:
        return {"status": "unknown", "message": "ReportStore not available"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_app_config() -> dict[str, Any]:
    """Application config validation."""
    try:
        from spiderfoot.config.app_config import AppConfig
        cfg = AppConfig()  # defaults
        errors = cfg.validate()
        if errors:
            return {
                "status": "degraded",
                "errors": [f"validation error {i+1}" for i, e in enumerate(errors[:5])],
            }
        return {"status": "up"}
    except ImportError:
        return {"status": "unknown", "message": "AppConfig not available"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_scan_hooks() -> dict[str, Any]:
    """Scan lifecycle hooks health and statistics."""
    try:
        from spiderfoot.scan.scan_hooks import get_scan_hooks
        hooks = get_scan_hooks()
        stats = hooks.stats()
        return {
            "status": "up",
            "total_events_fired": stats.get("total_events", 0),
            "listener_count": stats.get("listener_count", 0),
            "recent_events": stats.get("recent_count", 0),
        }
    except ImportError:
        return {"status": "unknown", "message": "scan_hooks module not available"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_module_timeout() -> dict[str, Any]:
    """Module timeout guard health and statistics."""
    try:
        from spiderfoot.plugins.module_timeout import get_timeout_guard
        guard = get_timeout_guard()
        stats = guard.stats()
        return {
            "status": "up",
            "default_timeout_s": guard.default_timeout,
            "total_guarded": stats.get("total_guarded", 0),
            "total_timeouts": stats.get("total_timeouts", 0),
            "hard_interrupt": guard.hard_interrupt,
        }
    except ImportError:
        return {"status": "unknown", "message": "module_timeout module not available"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


# -----------------------------------------------------------------------
# Prometheus metrics helper
# -----------------------------------------------------------------------

def _get_metrics_text() -> str:
    """Return Prometheus exposition text."""
    try:
        from spiderfoot.observability.metrics import get_registry
        registry = get_registry()
        return registry.expose()
    except ImportError:
        return "# spiderfoot_metrics_unavailable 1\n"
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return f"# spiderfoot_metrics_error 1\n"


# -----------------------------------------------------------------------
# MinIO object storage check
# -----------------------------------------------------------------------

def _check_qdrant() -> dict[str, Any]:
    """Qdrant, the vector database that holds the scan-finding index used by AI reports."""
    import urllib.request
    url = os.environ.get("SF_QDRANT_URL", "").strip().rstrip("/")
    if not url:
        host = os.environ.get("SF_QDRANT_HOST", "").strip() or "qdrant"
        port = os.environ.get("SF_QDRANT_PORT", "").strip() or "6333"
        url = f"http://{host}:{port}"
    try:
        with urllib.request.urlopen(f"{url}/healthz", timeout=3) as resp:
            if 200 <= resp.status < 300:
                return {"status": "up"}
            return {"status": "down", "message": f"Qdrant answered HTTP {resp.status}"}
    except Exception as e:
        log.warning("Qdrant health check failed: %s", type(e).__name__)
        return {"status": "down", "message": "Qdrant is not reachable"}


def _check_minio() -> dict[str, Any]:
    """Check MinIO/S3 connectivity and bucket status."""
    import os
    if not os.environ.get("SF_MINIO_ENDPOINT", "").strip():
        # Not deployed: do not probe the default localhost:9000, whose connection retries
        # added about six seconds to every dashboard refresh.
        return {"status": "unknown", "message": "Not configured"}
    try:
        from spiderfoot.storage.minio_manager import get_storage_manager
        mgr = get_storage_manager()
        return mgr.health_check()
    except ImportError:
        return {"status": "unknown", "message": "MinIO storage module not available"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_redis() -> dict[str, Any]:
    """Check Redis connectivity."""
    try:
        import os
        import redis as redis_lib
        url = os.environ.get("SF_REDIS_URL", "redis://redis:6379/0")
        r = redis_lib.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
        info = r.info("server")
        r.close()
        return {
            "status": "up",
            "redis_version": info.get("redis_version", "unknown"),
        }
    except ImportError:
        return {"status": "unknown", "message": "redis package not installed"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_celery() -> dict[str, Any]:
    """Check Celery worker availability via ping."""
    try:
        import os
        import redis as redis_lib
        url = os.environ.get("SF_REDIS_URL", "redis://redis:6379/0")
        r = redis_lib.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
        # Check if any celery worker keys exist in Redis
        worker_keys = r.keys("celery-task-meta-*")
        # Also check the broker queue length
        queue_len = r.llen("celery") or 0
        r.close()
        return {
            "status": "up",
            "completed_tasks": len(worker_keys),
            "pending_queue": int(queue_len),
        }
    except ImportError:
        return {"status": "unknown", "message": "redis package not installed"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


def _check_postgresql() -> dict[str, Any]:
    """Direct PostgreSQL connectivity check."""
    try:
        import os
        dsn = os.environ.get("SF_POSTGRES_DSN", "")
        if not dsn:
            return {"status": "unknown", "message": "SF_POSTGRES_DSN not set"}
        import psycopg2
        conn = psycopg2.connect(dsn, connect_timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT version()")
        version = cur.fetchone()[0]
        # Try to get scan count — table may not exist yet (lazy init)
        scan_count = None
        try:
            cur.execute("SELECT count(*) FROM tbl_scan_instance")
            scan_count = cur.fetchone()[0]
        except Exception:
            conn.rollback()  # clear the error state
        cur.close()
        conn.close()
        result = {
            "status": "up",
            "version": version.split(",")[0] if version else "unknown",
        }
        if scan_count is not None:
            result["scan_count"] = scan_count
        return result
    except ImportError:
        return {"status": "unknown", "message": "psycopg2 not installed"}
    except Exception as e:
        log.warning("Health check failed: %s", e)
        return {"status": "down", "message": "Service check failed"}


# -----------------------------------------------------------------------
# Tor check
# -----------------------------------------------------------------------

_TOR_CHECK_URL = "https://check.torproject.org/api/ip"
_TOR_OK_TTL = 300.0      # seconds a "working" result is reused
_TOR_RETRY_TTL = 60.0    # seconds any other result is reused
_tor_lock = threading.Lock()
_tor_state: dict[str, Any] = {"result": None, "at": 0.0, "key": "", "running": False}


def _probe_tor(host: str, port: int) -> dict[str, Any]:
    """Is the Tor SOCKS port answering, and does a request through it leave via Tor?"""
    import socket
    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            sock.settimeout(4)
            sock.sendall(b"\x05\x01\x00")          # SOCKS5 greeting, "no authentication"
            if sock.recv(2) != b"\x05\x00":
                return {"status": "down", "message": f"{host}:{port} is not answering as a SOCKS5 proxy"}
    except OSError:
        return {"status": "down", "message": f"Tor proxy {host}:{port} is not reachable"}
    try:
        import requests
        proxy = f"socks5h://{host}:{port}"
        resp = requests.get(_TOR_CHECK_URL, proxies={"http": proxy, "https": proxy}, timeout=25)
        if resp.ok and resp.json().get("IsTor") is True:
            return {"status": "up", "message": "Working: requests leave through the Tor network"}
        return {"status": "degraded", "message": "Proxy answers, but the test request did not leave through Tor"}
    except Exception as e:
        log.info("Tor exit check failed: %s", type(e).__name__)
        return {"status": "degraded", "message": "Proxy answers, but Tor has no working circuit yet"}


_TOR_REDIS_PREFIX = "sf:health:tor:"


def _tor_redis():
    """A Redis client for the shared Tor result, or None when Redis is not available."""
    url = os.environ.get("SF_REDIS_URL", "").strip()
    if not url:
        return None
    try:
        import redis as redis_lib
        return redis_lib.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)
    except Exception:
        return None


def _check_tor_shared(r, host: str, port: int) -> dict[str, Any] | None:
    """The Tor check using Redis as the one place the result lives.

    Every API process runs its own copy of the dashboard code. With the result kept in each process, a
    dashboard refresh showed "working" or "checking" depending on which process answered (9 of 12 readings in
    one minute). In Redis the first process to find no result takes a lock and probes; everyone else sees the
    same stored answer until it expires. Returns None when Redis cannot be used, so the caller falls back to the
    per-process state.
    """
    import json as _json
    key = f"{host}:{port}"
    try:
        raw = r.get(f"{_TOR_REDIS_PREFIX}result:{key}")
        if raw:
            return {**_json.loads(raw), "endpoint": key}
        if r.set(f"{_TOR_REDIS_PREFIX}lock:{key}", "1", nx=True, ex=90):
            def _run() -> None:
                result = _probe_tor(host, port)
                ttl = int(_TOR_OK_TTL if result.get("status") == "up" else _TOR_RETRY_TTL)
                try:
                    r.setex(f"{_TOR_REDIS_PREFIX}result:{key}", ttl, _json.dumps(result))
                    r.delete(f"{_TOR_REDIS_PREFIX}lock:{key}")
                except Exception as e:
                    log.info("Tor health result could not be stored: %s", type(e).__name__)

            threading.Thread(target=_run, name="tor-health", daemon=True).start()
        return {"status": "unknown", "message": "Checking..."}
    except Exception as e:
        log.info("Tor health check could not use Redis: %s", type(e).__name__)
        return None


def _check_tor() -> dict[str, Any]:
    """Tor status for the dashboard: working, not working, or not configured.

    The probe opens a Tor circuit, which is slow, so it runs in the background and its result
    is reused for a few minutes; the dashboard never waits for it. The result is shared between
    API processes through Redis when it is available.
    """
    try:
        from spiderfoot.api.dependencies import get_app_config
        from spiderfoot.sflib.proxy import as_bool
        opts = get_app_config().get_config()
        enabled = as_bool(opts.get("_tor_enabled", False))
        host = str(opts.get("_tor_host") or "").strip()
        port = int(opts.get("_tor_port") or 0)
    except Exception as e:
        log.warning("Tor health check could not read the configuration: %s", e)
        return {"status": "unknown", "message": "Configuration unavailable"}
    if not enabled or not host or not port:
        return {"status": "unknown", "message": "Not configured (turned off in Settings > Tor)"}

    r = _tor_redis()
    if r is not None:
        shared = _check_tor_shared(r, host, port)
        if shared is not None:
            return shared

    key = f"{host}:{port}"
    now = time.monotonic()
    with _tor_lock:
        cached = _tor_state["result"] if _tor_state["key"] == key else None
        ttl = _TOR_OK_TTL if cached and cached.get("status") == "up" else _TOR_RETRY_TTL
        fresh = cached is not None and now - _tor_state["at"] < ttl
        if not fresh and not _tor_state["running"]:
            _tor_state["running"] = True

            def _run() -> None:
                result = _probe_tor(host, port)
                with _tor_lock:
                    _tor_state.update(result=result, at=time.monotonic(), key=key, running=False)

            threading.Thread(target=_run, name="tor-health", daemon=True).start()
    if cached is None:
        return {"status": "unknown", "message": "Checking..."}
    return {**cached, "endpoint": key}


# -----------------------------------------------------------------------
# Subsystem registry — run all checks
# -----------------------------------------------------------------------

_SUBSYSTEM_CHECKS = {
    "postgresql": _check_postgresql,
    "redis": _check_redis,
    "celery": _check_celery,
    "qdrant": _check_qdrant,
    "vector": _check_vector,
    "minio": _check_minio,
    "tor": _check_tor,
    "app_config": _check_app_config,
    "report_storage": _check_report_storage,
    "scan_hooks": _check_scan_hooks,
    "module_timeout": _check_module_timeout,
}

_startup_time = time.time()
_startup_complete = False


# Core subsystems whose failure should affect overall status.
# Optional/auxiliary subsystems report individual status but
# do not drag the overall health to "down".
# minio/vector are only core if their endpoints are actually configured.
def _get_core_subsystems() -> set[str]:
    """Return the set of core subsystems based on current configuration."""
    import os
    core = {"postgresql", "redis", "celery"}
    if os.environ.get("SF_MINIO_ENDPOINT", "").strip():
        core.add("minio")
    if os.environ.get("SF_QDRANT_HOST", "").strip() or os.environ.get("SF_VECTOR_URL", "").strip():
        core.add("qdrant")
    return core


def run_all_checks() -> dict[str, Any]:
    """Execute all registered subsystem checks and aggregate."""
    components: dict[str, Any] = {}
    overall = "up"
    core_subsystems = _get_core_subsystems()

    for name, check_fn in _SUBSYSTEM_CHECKS.items():
        t0 = time.monotonic()
        try:
            result = check_fn()
        except Exception as e:
            log.warning("Health check failed: %s", e)
            result = {"status": "down", "message": "Service check failed"}
        elapsed = (time.monotonic() - t0) * 1000
        result["latency_ms"] = round(elapsed, 2)
        components[name] = result

        # Only core subsystems affect the overall status
        if name not in core_subsystems:
            continue

        status = result.get("status", "unknown")
        if status == "down":
            overall = "down"
        elif status == "degraded" and overall == "up":
            overall = "degraded"

    return {
        "status": overall,
        "uptime_seconds": round(time.time() - _startup_time, 1),
        "components": components,
    }


def run_single_check(name: str) -> dict[str, Any] | None:
    """Run a single named check. Returns None if not found."""
    check_fn = _SUBSYSTEM_CHECKS.get(name)
    if check_fn is None:
        return None
    t0 = time.monotonic()
    try:
        result = check_fn()
    except Exception as e:
        log.warning("Health check failed: %s", e)
        result = {"status": "down", "message": "Service check failed"}
    result["latency_ms"] = round((time.monotonic() - t0) * 1000, 2)
    return result


def mark_startup_complete() -> None:
    """Mark application startup as done."""
    global _startup_complete
    _startup_complete = True
    log.info("Health: startup marked complete")


# -----------------------------------------------------------------------
# FastAPI router
# -----------------------------------------------------------------------

if not HAS_FASTAPI:
    class _StubRouter:
        """Stub router for when dependencies are unavailable."""
        pass
    router = _StubRouter()
else:
    router = APIRouter()

    @router.get(
        "/health",
        summary="Overall health check",
        description="Combined liveness and readiness. Returns 200 if healthy, 503 if degraded/down.",
    )
    async def health() -> Response:
        """Return overall health status of all subsystems."""
        result = run_all_checks()
        status_code = 200 if result["status"] == "up" else 503
        return Response(
            content=_json_dumps(result),
            media_type="application/json",
            status_code=status_code,
        )

    @router.get(
        "/health/live",
        summary="Liveness probe",
        description="Returns 200 if the process is alive. Always succeeds.",
    )
    async def liveness() -> dict[str, Any]:
        """Return liveness probe indicating the process is alive."""
        return {
            "status": "up",
            "uptime_seconds": round(time.time() - _startup_time, 1),
            "python_version": platform.python_version(),
        }

    @router.get(
        "/health/ready",
        summary="Readiness probe",
        description="Returns 200 if the service can handle traffic, 503 otherwise.",
    )
    async def readiness() -> Response:
        """Return readiness probe indicating ability to handle traffic."""
        result = run_all_checks()
        status_code = 200 if result["status"] in ("up", "degraded") else 503
        return Response(
            content=_json_dumps(result),
            media_type="application/json",
            status_code=status_code,
        )

    @router.get(
        "/health/startup",
        summary="Startup probe",
        description="Returns 200 once application initialization is complete.",
    )
    async def startup_probe() -> Response:
        """Return startup probe indicating initialization completion."""
        status_code = 200 if _startup_complete else 503
        return Response(
            content=_json_dumps({
                "status": "up" if _startup_complete else "starting",
                "startup_complete": _startup_complete,
                "uptime_seconds": round(time.time() - _startup_time, 1),
            }),
            media_type="application/json",
            status_code=status_code,
        )

    @router.get(
        "/health/dashboard",
        summary="Full health dashboard",
        description="Comprehensive status overview of all subsystems.",
    )
    async def dashboard() -> dict[str, Any]:
        """Return comprehensive status overview of all subsystems."""
        result = run_all_checks()
        result["subsystems_available"] = list(_SUBSYSTEM_CHECKS.keys())
        result["python"] = {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        }
        return result

    # NOTE: declared before /health/{component_name} so the parameterized route
    # does not shadow it (Starlette matches in declaration order).
    @router.get(
        "/health/shutdown",
        summary="Shutdown manager status",
        description="Shows registered services and shutdown state.",
    )
    async def shutdown_status() -> dict[str, Any]:
        """Return shutdown manager status and registered services."""
        from spiderfoot.ops.graceful_shutdown import get_shutdown_coordinator
        mgr = get_shutdown_coordinator()
        return mgr.status()

    @router.get(
        "/health/{component_name}",
        summary="Individual component health",
        description="Check health of a specific subsystem by name.",
    )
    async def component_health(component_name: str) -> Response:
        """Check health of a specific subsystem by name."""
        result = run_single_check(component_name)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown component: {component_name}. "
                       f"Available: {', '.join(_SUBSYSTEM_CHECKS.keys())}",
            )
        status_code = 200 if result.get("status") != "down" else 503
        return Response(
            content=_json_dumps(result),
            media_type="application/json",
            status_code=status_code,
        )

    @router.get(
        "/metrics",
        summary="Prometheus metrics",
        description="Prometheus-compatible metrics in text exposition format.",
    )
    async def metrics() -> PlainTextResponse:
        """Return Prometheus-compatible metrics in text exposition format."""
        return PlainTextResponse(
            content=_get_metrics_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @router.get(
        "/version",
        summary="API version info",
        description="Returns current and supported API versions.",
    )
    async def version_info() -> dict[str, Any]:
        """Return current and supported API version information."""
        from spiderfoot.api.versioning import get_version_info
        from spiderfoot import __version__
        info = get_version_info()
        info["app_version"] = __version__
        return info

# -----------------------------------------------------------------------
# Utility
# -----------------------------------------------------------------------

def _json_dumps(obj: Any) -> str:
    """JSON serialisation without extra dependencies."""
    import json
    return json.dumps(obj, default=str)
