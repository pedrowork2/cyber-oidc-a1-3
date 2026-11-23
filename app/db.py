"""Persistência local (SQLite): tabela de usuários (4.1) e sessões server-side (4.4)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,      -- identificador interno
    user_name   TEXT    NOT NULL UNIQUE,                -- login exibido (e-mail verificado)
    full_name   TEXT,                                   -- nome completo para exibição
    oidc_sub    TEXT    NOT NULL UNIQUE,                -- claim sub: chave de vínculo
    oidc_iss    TEXT    NOT NULL,                       -- emissor do sub (vínculo = iss + sub)
    role        TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at  TEXT    NOT NULL,                       -- auditoria
    last_login_at TEXT,
    UNIQUE (oidc_iss, oidc_sub)
);

-- O cookie carrega o sessionID; no banco fica apenas o SHA-256 dele.
-- Se o banco vazar, os IDs de sessão ativos não vazam junto.
CREATE TABLE IF NOT EXISTS sessions (
    sid_hash         TEXT PRIMARY KEY,
    user_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
    data             TEXT NOT NULL DEFAULT '{}',
    created_at       REAL NOT NULL,
    last_seen        REAL NOT NULL,
    absolute_expiry  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    event     TEXT NOT NULL,
    detail    TEXT
);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


class Database:
    def __init__(self, path: str):
        self.path = path
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # ------------------------------------------------------------ usuários
    def find_user_by_sub(self, iss: str, sub: str) -> sqlite3.Row | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM users WHERE oidc_iss = ? AND oidc_sub = ?",
                             (iss, sub)).fetchone()

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def list_users(self) -> list[sqlite3.Row]:
        with self._conn() as c:
            return c.execute("SELECT * FROM users ORDER BY id").fetchall()

    def create_user(self, *, iss: str, sub: str, user_name: str, full_name: str | None,
                    role: str = "user") -> int:
        with self._conn() as c:
            # user_name é único; se o e-mail já estiver associado a OUTRO sub
            # (ex.: e-mail reciclado), não sobrescrevemos — desambiguamos.
            base, candidate, n = user_name, user_name, 1
            while c.execute("SELECT 1 FROM users WHERE user_name = ?", (candidate,)).fetchone():
                n += 1
                candidate = f"{base}#{n}"
            cur = c.execute(
                "INSERT INTO users (user_name, full_name, oidc_sub, oidc_iss, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (candidate, full_name, sub, iss, role, utcnow_iso()))
            return cur.lastrowid

    def touch_login(self, user_id: int, full_name: str | None) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET last_login_at = ?, full_name = COALESCE(?, full_name) "
                      "WHERE id = ?", (utcnow_iso(), full_name, user_id))

    def set_role(self, user_id: int, role: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))

    # ------------------------------------------------------------- sessões
    def create_session(self, sid: str, user_id: int | None, data: dict, absolute_ttl: int) -> None:
        now = time.time()
        with self._conn() as c:
            c.execute("INSERT INTO sessions (sid_hash, user_id, data, created_at, last_seen, "
                      "absolute_expiry) VALUES (?, ?, ?, ?, ?, ?)",
                      (sid_hash(sid), user_id, json.dumps(data), now, now, now + absolute_ttl))

    def get_session(self, sid: str) -> sqlite3.Row | None:
        with self._conn() as c:
            return c.execute("SELECT * FROM sessions WHERE sid_hash = ?",
                             (sid_hash(sid),)).fetchone()

    def update_session(self, sid: str, data: dict | None = None) -> None:
        with self._conn() as c:
            if data is None:
                c.execute("UPDATE sessions SET last_seen = ? WHERE sid_hash = ?",
                          (time.time(), sid_hash(sid)))
            else:
                c.execute("UPDATE sessions SET last_seen = ?, data = ? WHERE sid_hash = ?",
                          (time.time(), json.dumps(data), sid_hash(sid)))

    def delete_session(self, sid: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE sid_hash = ?", (sid_hash(sid),))

    def purge_expired(self, idle_ttl: int) -> None:
        now = time.time()
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE absolute_expiry < ? OR last_seen < ?",
                      (now, now - idle_ttl))

    # ------------------------------------------------------------ auditoria
    def audit(self, event: str, detail: str = "") -> None:
        with self._conn() as c:
            c.execute("INSERT INTO audit_log (at, event, detail) VALUES (?, ?, ?)",
                      (utcnow_iso(), event, detail[:2000]))
