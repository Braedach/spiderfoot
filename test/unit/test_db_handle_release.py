"""A dropped DbCore handle must return its pooled connection, and DB errors must not carry the DSN password."""
import gc
import threading
from unittest import mock

from spiderfoot.db.db_core import DbCore


def _handle(pool):
    h = DbCore.__new__(DbCore)
    h.dbhLock = threading.RLock()
    h.dbh = mock.Mock()
    h.conn = mock.Mock()
    h._owns_pooled_conn = True
    return h


def test_dropped_handle_returns_connection_to_pool():
    pool = mock.Mock(closed=False)
    with mock.patch.object(DbCore, "_pool", pool):
        h = _handle(pool)
        conn = h.conn
        del h
        gc.collect()
        pool.putconn.assert_called_once_with(conn)


def test_context_manager_and_double_close():
    pool = mock.Mock(closed=False)
    with mock.patch.object(DbCore, "_pool", pool):
        with _handle(pool) as h:
            pass
        h.close()
        assert pool.putconn.call_count == 1


def test_dsn_password_is_redacted():
    out = DbCore._redact_dsn("cannot reach postgresql://user:s3cret@db:5432/sf now")
    assert "s3cret" not in out and "user" not in out
    assert "postgresql://***@db:5432/sf" in out
