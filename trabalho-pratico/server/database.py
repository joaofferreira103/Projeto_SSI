import sqlite3
import os
import threading


from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


# Path to the SQLite database file, relative to this module
DB_PATH = os.path.join(os.path.dirname(__file__), "chat_server.db")

# scrypt parameters — balance between security and performance.
# Using cryptography.hazmat.primitives.kdf.scrypt.Scrypt (NOT hashlib.scrypt)
# because the project mandates the `cryptography` library for all crypto primitives.
# The parameters are identical in meaning to hashlib.scrypt:
#   n: CPU/memory cost factor (must be power of 2). 2^14 suitable for interactive login.
#   r: block size (8 is the standard default).
#   p: parallelization factor (1 is sufficient here).
#   length: derived key length in bytes (32 = 256-bit).
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32


class Database:
    """
    Manages all persistent storage for the chat server.

    Thread safety: SQLite connections cannot be shared across threads.
    Solution: each Database instance uses check_same_thread=False combined
    with an explicit threading.Lock() around every write operation.
    Reads are safe to run concurrently on SQLite's default journal mode.
    """

    def __init__(self, db_path: str = DB_PATH):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row  # rows accessible as dicts
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        """
        Create tables if they don't already exist.

        Using IF NOT EXISTS means this is idempotent — safe to call on
        every server startup without wiping existing data.

        Schema design notes:
          - username is the primary key (unique identifier per the spec)
          - password_hash stores "salt_hex:hash_hex"
          - created_at is stored as ISO8601 text (SQLite has no native datetime)
          - Future tables (messages, public_keys) will reference username via FK
        """
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    username     TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
                );
            """)
            self._conn.commit()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        """
        Register a new user.

        Returns:
            (True, "ok") on success.
            (False, reason) if the username is taken or input is invalid.

        Security:
            - Generates a fresh random 16-byte salt per user
            - Hashes with scrypt before storing
            - Never stores or logs the plaintext password
        """
        if not username or not password:
            return False, "Username and password cannot be empty"

        if len(username) > 32:
            return False, "Username too long (max 32 characters)"

        # Validate username characters to prevent injection / display issues
        if not username.replace("_", "").replace("-", "").isalnum():
            return False, "Username may only contain letters, numbers, - and _"

        password_hash = self._hash_password(password)

        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                self._conn.commit()
            return True, "Registered successfully"

        except sqlite3.IntegrityError:
            # PRIMARY KEY constraint violation = username already exists
            return False, "Username already taken"

    def verify_user(self, username: str, password: str) -> tuple[bool, str]:
        """
        Verify login credentials.

        Returns:
            (True, "ok") if credentials match.
            (False, reason) otherwise.

        Security:
            - Uses constant-time comparison via hmac.compare_digest inside
              scrypt verification to prevent timing attacks
            - Returns the same generic error for "user not found" and
              "wrong password" to prevent username enumeration
        """
        row = self._conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None:
            # User doesn't exist — still run a fake hash to prevent timing attacks
            # (an attacker timing the response could distinguish "no user" from
            # "wrong password" if we returned immediately here)
            self._hash_password(password)  # dummy work
            return False, "Invalid username or password"

        stored_hash = row["password_hash"]
        if self._verify_password(password, stored_hash):
            return True, "Login successful"
        else:
            return False, "Invalid username or password"

    def user_exists(self, username: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row is not None

    # -------------------------------------------------------------------------
    # Password hashing helpers (private)
    # -------------------------------------------------------------------------

    @staticmethod
    def _hash_password(password: str) -> str:
        """
        Hash a plaintext password with a fresh random salt using scrypt
        from the `cryptography` library.

        Returns a string in the format "salt_hex:hash_hex" suitable for storage.

        WHY cryptography.hazmat.primitives.kdf.scrypt.Scrypt:
          The project mandates the `cryptography` library for all crypto primitives.
          This KDF is functionally identical to hashlib.scrypt but goes through
          the hazmat layer, which makes all crypto usage auditable in one place
          and consistent with the rest of the project (future AES, ECDH, etc.).
        """
        salt = os.urandom(16)  # 128-bit random salt
        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))
        return f"{salt.hex()}:{key.hex()}"

    @staticmethod
    def _verify_password(password: str, stored: str) -> bool:
        """
        Verify a plaintext password against a stored "salt_hex:hash_hex".

        Uses Scrypt.verify() from the `cryptography` library, which raises
        InvalidKey on mismatch instead of returning False — and internally
        uses a constant-time comparison to prevent timing attacks.
        """
        try:
            salt_hex, hash_hex = stored.split(":", 1)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except (ValueError, AttributeError):
            return False

        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            backend=default_backend(),
        )
        try:
            kdf.verify(password.encode("utf-8"), expected)
            return True
        except InvalidKey:
            return False

    def close(self) -> None:
        self._conn.close()
        

        
## PUBLIC KEY MANAGEMENT TABLE:

    def _initialize_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    username      TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
                );

                -- NOVA TABELA: chaves públicas efémeras por sessão.
                -- Uma entrada por utilizador autenticado. Substituída
                -- a cada novo login (chaves efémeras = forward secrecy).
                CREATE TABLE IF NOT EXISTS public_keys (
                    username    TEXT PRIMARY KEY REFERENCES users(username),
                    public_key  TEXT NOT NULL,        -- hex dos 32 bytes Raw
                    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
            """)
            self._conn.commit()

    def store_public_key(self, username: str, public_key_hex: str) -> None:
        """
        Armazena (ou substitui) a chave pública de um utilizador.
        INSERT OR REPLACE garante que um novo login limpa a chave antiga.
        """
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO public_keys (username, public_key) VALUES (?, ?)",
                (username, public_key_hex),
            )
            self._conn.commit()

    def get_public_key(self, username: str) -> str | None:
        """
        Devolve a chave pública hex de um utilizador, ou None se não existir
        (utilizador não está online / nunca fez upload da chave).
        """
        row = self._conn.execute(
            "SELECT public_key FROM public_keys WHERE username = ?",
            (username,),
        ).fetchone()
        return row["public_key"] if row else None

    def remove_public_key(self, username: str) -> None:
        """Limpa a chave ao fazer logout — o servidor não guarda chaves de sessões passadas."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM public_keys WHERE username = ?", (username,)
            )
            self._conn.commit()