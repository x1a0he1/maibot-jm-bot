"""Store JM download permissions using the existing scope database."""
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
import sqlite3
import time


@dataclass(frozen=True)
class Scope:
    kind: str
    owner_id: int

    def __post_init__(self) -> None:
        if self.kind not in {"private", "group"} or self.owner_id < 1:
            raise ValueError("会话类型或 QQ 号无效")

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.owner_id}"


@dataclass(frozen=True)
class ScopePolicy:
    download_enabled: bool = False
    download_blacklisted: bool = False


class ConversationStateStore:
    """Keep group and private scopes distinct across queue and admin processes."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS conversation_policies (
                    scope_key TEXT PRIMARY KEY,
                    download_enabled INTEGER NOT NULL DEFAULT 0,
                    download_blacklisted INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL,
                    version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS global_policies (
                    key TEXT PRIMARY KEY, enabled INTEGER NOT NULL, updated_at REAL NOT NULL
                );
                """
            )
            conn.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(conversation_policies)")}
            if "download_blacklisted" not in columns:
                conn.execute("ALTER TABLE conversation_policies ADD COLUMN download_blacklisted INTEGER NOT NULL DEFAULT 0")
            if "version" not in columns:
                conn.execute("ALTER TABLE conversation_policies ADD COLUMN version INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.db_path, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            with conn:
                yield conn

    @staticmethod
    def _scope_key(scope: Scope | str) -> str:
        if isinstance(scope, Scope):
            return scope.key
        kind, owner = scope.split(":", 1)
        return Scope(kind, int(owner)).key

    def has_policy(self, scope: Scope | str) -> bool:
        with self._connection() as conn:
            return conn.execute(
                "SELECT 1 FROM conversation_policies WHERE scope_key=?", (self._scope_key(scope),)
            ).fetchone() is not None

    def get_policy(self, scope: Scope | str) -> ScopePolicy:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT download_enabled, download_blacklisted FROM conversation_policies WHERE scope_key=?",
                (self._scope_key(scope),),
            ).fetchone()
        return ScopePolicy(bool(row[0]), bool(row[1])) if row else ScopePolicy()

    def policy_version(self, scope: Scope | str) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT version FROM conversation_policies WHERE scope_key=?", (self._scope_key(scope),)
            ).fetchone()
        return int(row[0]) if row else 0

    def list_policies(self) -> list[dict[str, object]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT scope_key, download_enabled, download_blacklisted, updated_at "
                "FROM conversation_policies ORDER BY scope_key"
            ).fetchall()
        return [dict(row) for row in rows]

    def set_policy(
        self, scope: Scope | str, *, expected_version: int | None = None,
        download_enabled: bool | None = None, download_blacklisted: bool | None = None,
    ) -> ScopePolicy:
        key = self._scope_key(scope)
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT download_enabled, download_blacklisted, version FROM conversation_policies WHERE scope_key=?", (key,)
            ).fetchone()
            enabled, blacklisted, version = row if row is not None else (False, False, 0)
            if expected_version is not None and expected_version != version:
                raise ValueError("policy version changed")
            policy = ScopePolicy(
                bool(enabled) if download_enabled is None else download_enabled,
                bool(blacklisted) if download_blacklisted is None else download_blacklisted,
            )
            conn.execute(
                """
                INSERT INTO conversation_policies(scope_key, download_enabled, download_blacklisted, updated_at, version)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(scope_key) DO UPDATE SET
                    download_enabled=excluded.download_enabled,
                    download_blacklisted=excluded.download_blacklisted,
                    updated_at=excluded.updated_at, version=excluded.version
                """,
                (key, policy.download_enabled, policy.download_blacklisted, time.time(), version + 1),
            )
        return policy

    def global_enabled(self, key: str) -> bool:
        if key != "download":
            raise ValueError("无效的下载策略")
        with self._connection() as conn:
            row = conn.execute("SELECT enabled FROM global_policies WHERE key=?", (key,)).fetchone()
        return row is None or bool(row[0])

    def set_global_enabled(self, key: str, enabled: bool) -> None:
        if key != "download":
            raise ValueError("无效的下载策略")
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO global_policies(key, enabled, updated_at) VALUES(?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at",
                (key, enabled, time.time()),
            )

    def permitted(self, scope: Scope | str, domain: str = "download") -> bool:
        policy = self.get_policy(scope)
        return self.global_enabled(domain) and policy.download_enabled and not policy.download_blacklisted
