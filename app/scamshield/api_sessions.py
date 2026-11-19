"""Server-issued browser sessions and short-lived trusted plan drafts."""

from collections import OrderedDict
import re
from secrets import token_urlsafe
import sqlite3
from threading import Lock
from time import monotonic, time
from uuid import uuid4

from .events import session_reference
from .plan_models import AnalysisPlanDraft


COOKIE_NAME = "scamshield_session"
SESSION_SECONDS = 7 * 24 * 60 * 60
DRAFT_SECONDS = 60 * 60
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class BrowserSessions:
    def __init__(self, path):
        self._lock = Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        try:
            with self._db:
                self._db.execute(
                    """CREATE TABLE IF NOT EXISTS browser_sessions (
                       token_hash TEXT PRIMARY KEY, owner_id TEXT NOT NULL UNIQUE,
                       expires_at INTEGER NOT NULL)"""
                )
                self._db.execute(
                    "CREATE INDEX IF NOT EXISTS browser_sessions_expiry ON browser_sessions(expires_at)"
                )
        except sqlite3.Error:
            self._db.close()
            raise

    def create(self):
        token, owner_id = token_urlsafe(32), uuid4().hex
        now = int(time())
        with self._lock, self._db:
            self._db.execute("DELETE FROM browser_sessions WHERE expires_at <= ?", (now,))
            self._db.execute(
                "INSERT INTO browser_sessions VALUES (?, ?, ?)",
                (session_reference(token), owner_id, now + SESSION_SECONDS),
            )
        return token, owner_id

    def resolve(self, token):
        if not token or TOKEN.fullmatch(token) is None:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT owner_id FROM browser_sessions WHERE token_hash = ? AND expires_at > ?",
                (session_reference(token), int(time())),
            ).fetchone()
        return row[0] if row else None

    def close(self):
        with self._lock:
            self._db.close()


class PlanDrafts:
    def __init__(self):
        self._lock = Lock()
        self._items: OrderedDict[tuple[str, str], tuple[float, AnalysisPlanDraft]] = OrderedDict()

    def keep(self, owner_id, draft):
        with self._lock:
            now = monotonic()
            while self._items:
                oldest = next(iter(self._items.values()))[0]
                if oldest > now and len(self._items) < 1024:
                    break
                self._items.popitem(last=False)
            self._items[(owner_id, draft.analysis_id)] = (now + DRAFT_SECONDS, draft)

    def get(self, owner_id, analysis_id):
        with self._lock:
            key = (owner_id, analysis_id)
            item = self._items.get(key)
            if item and item[0] > monotonic():
                return item[1]
            self._items.pop(key, None)
        return None
