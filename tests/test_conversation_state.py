import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from jmbot.core.conversation_state import ConversationStateStore, Scope


class ConversationStateTest(unittest.TestCase):
    def test_download_policy_keeps_scopes_and_checks_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ConversationStateStore(Path(tmp) / "scopes.sqlite3")
            group = Scope("group", 42)
            private = Scope("private", 42)
            store.set_policy(group, download_enabled=True)
            version = store.policy_version(group)
            self.assertTrue(store.permitted(group))
            self.assertFalse(store.permitted(private))
            store.set_policy(group, expected_version=version, download_blacklisted=True)
            self.assertFalse(store.permitted(group))
            with self.assertRaisesRegex(ValueError, "version changed"):
                store.set_policy(group, expected_version=version, download_enabled=True)
            store.set_policy(private, download_enabled=True)
            store.set_global_enabled("download", False)
            self.assertFalse(store.permitted(private))
            with self.assertRaises(ValueError):
                store.get_policy("42")

    def test_legacy_policy_data_still_reads_and_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scopes.sqlite3"
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.executescript("""
                    CREATE TABLE conversation_policies (
                        scope_key TEXT PRIMARY KEY,
                        chat_enabled INTEGER NOT NULL DEFAULT 1,
                        download_enabled INTEGER NOT NULL DEFAULT 0,
                        updated_at REAL NOT NULL
                    );
                    INSERT INTO conversation_policies VALUES ('group:42', 0, 1, 0);
                """)
            store = ConversationStateStore(path)
            self.assertTrue(store.permitted("group:42"))
            store.set_policy("group:42", download_blacklisted=True)
            self.assertFalse(store.permitted("group:42"))
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(conn.execute("SELECT chat_enabled FROM conversation_policies").fetchone()[0], 0)
