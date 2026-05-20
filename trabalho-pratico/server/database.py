"""
server/database.py — Persistent storage for the chat server.

"""

import sqlite3
import os
import threading

from common.crypto import hash_password, verify_password


DB_PATH = os.path.join(os.path.dirname(__file__), "chat_server.db")


class Database:
    """
    Manages all persistent storage for the chat server.

    Thread safety: SQLite connections cannot be shared across threads.
    
    """

    def __init__(self, db_path: str = DB_PATH):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        """
        Create tables if they don't already exist (idempotent).

        Schema:
          users            — credentials; username is the primary key.
          public_keys      — one ephemeral X25519 public key per online user.
                             Replaced on every new login (forward secrecy).
                             Deleted on logout.
          offline_messages — messages for offline users, stored until delivery.
        """
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    username      TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS public_keys (
                    username    TEXT PRIMARY KEY REFERENCES users(username),
                    public_key  TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS offline_messages (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient       TEXT NOT NULL REFERENCES users(username),
                    sender          TEXT NOT NULL REFERENCES users(username),
                    ciphertext_hex  TEXT NOT NULL,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE INDEX IF NOT EXISTS idx_offline_recipient 
                ON offline_messages(recipient);
            """)
            self._conn.commit()

    # -------------------------------------------------------------------------
    # User management
    # -------------------------------------------------------------------------

    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        """
        Register a new user with a scrypt-hashed password.

        Returns (True, "ok") on success, (False, reason) otherwise.
        """
        if not username or not password:
            return False, "Username and password cannot be empty"
        if len(username) > 32:
            return False, "Username too long (max 32 characters)"
        if not username.replace("_", "").replace("-", "").isalnum():
            return False, "Username may only contain letters, numbers, - and _"

        password_hash = hash_password(password)

        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                self._conn.commit()
            return True, "Registered successfully"
        except sqlite3.IntegrityError:
            return False, "Username already taken"

    def verify_user(self, username: str, password: str) -> tuple[bool, str]:
        """
        Verify login credentials.

        Returns (True, "ok") or (False, reason).
        Always does the full scrypt work even when the user doesn't exist,
        to prevent timing-based username enumeration.
        """
        row = self._conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None:
            hash_password(password)   
            return False, "Invalid username or password"

        if verify_password(password, row["password_hash"]):
            return True, "Login successful"
        return False, "Invalid username or password"

    def user_exists(self, username: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row is not None

    # -------------------------------------------------------------------------
    # Ephemeral public key management
    # -------------------------------------------------------------------------

    def store_public_key(self, username: str, public_key_hex: str) -> None:
        """Store (or replace) a user's ephemeral X25519 public key."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO public_keys (username, public_key) VALUES (?, ?)",
                (username, public_key_hex),
            )
            self._conn.commit()

    def get_public_key(self, username: str) -> str | None:
        """Return the hex public key for a user, or None if not present."""
        row = self._conn.execute(
            "SELECT public_key FROM public_keys WHERE username = ?",
            (username,),
        ).fetchone()
        return row["public_key"] if row else None

    def remove_public_key(self, username: str) -> None:
        """Delete a user's public key on logout."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM public_keys WHERE username = ?", (username,)
            )
            self._conn.commit()

    # -------------------------------------------------------------------------
    # Offline message management
    # -------------------------------------------------------------------------

    def store_offline_message(self, recipient: str, sender: str, ciphertext_hex: str) -> None:
        """
        Store an encrypted message for delivery when the recipient logs in.
        
        Args:
            recipient: The username who should receive this message
            sender: The username who sent this message
            ciphertext_hex: The encrypted message (hex-encoded, AES-256-GCM)
        """
        with self._lock:
            self._conn.execute(
                """INSERT INTO offline_messages 
                   (recipient, sender, ciphertext_hex, created_at) 
                   VALUES (?, ?, ?, datetime('now'))""",
                (recipient, sender, ciphertext_hex),
            )
            self._conn.commit()

    def get_offline_messages(self, recipient: str) -> list[dict]:
        """
        Retrieve all pending offline messages for a user, ordered by time.
        
        Args:
            recipient: The username to fetch messages for
            
        Returns:
            List of dicts with keys: sender, ciphertext_hex, created_at
        """
        with self._lock:
            rows = self._conn.execute(
                """SELECT sender, ciphertext_hex, created_at 
                   FROM offline_messages 
                   WHERE recipient = ? 
                   ORDER BY created_at ASC""",
                (recipient,),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_offline_messages(self, recipient: str) -> None:
        """
        Delete all offline messages for a user (after delivery on login).
        
        Args:
            recipient: The username whose offline messages should be deleted
        """
        with self._lock:
            self._conn.execute(
                "DELETE FROM offline_messages WHERE recipient = ?",
                (recipient,),
            )
            self._conn.commit()

    def count_offline_messages(self, recipient: str) -> int:
        """
        Count the number of pending offline messages for a user.
        
        Args:
            recipient: The username to count messages for
            
        Returns:
            Number of offline messages (0 if none)
        """
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM offline_messages WHERE recipient = ?",
            (recipient,),
        ).fetchone()
        return row["cnt"]

    def close(self) -> None:
        self._conn.close()