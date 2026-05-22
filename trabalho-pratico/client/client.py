"""
client/client.py — E2EE chat client.

"""

import socket
import threading
import sys
import os
import getpass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.protocol import send_json, recv_json
from common.crypto import (
    generate_x25519_keypair,
    derive_shared_secret,
    public_bytes_to_hex,
    hex_to_public_bytes,
    encrypt_message,
    decrypt_message,
    generate_offline_keypair,
    encrypt_offline_key,
    decrypt_offline_key,
    derive_offline_shared_secret,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
import json

HOST = "127.0.0.1"
PORT = 9000

# Ephemeral private key for this session
_private_key = None

# Offline private key (persistent, loaded from encrypted file)
_offline_private_key = None

# Derived AES-256-GCM keys per peer: {username: bytes}
_session_keys: dict[str, bytes] = {}

# Offline shared secrets per peer: {username: bytes}
_offline_session_keys: dict[str, bytes] = {}

# Who we're currently "talking to"
_current_peer: str | None = None

_message_counts: dict[str, int] = {}

KEY_ROTATION_THRESHOLD = 50  # rotaciona a cada 50 mensagens enviadas


# ---------------------------------------------------------------------------
# Offline key file management
# ---------------------------------------------------------------------------

def _get_offline_key_path(username: str) -> str:
    """
    Return the path to the encrypted offline key file.
    Creates ~/.chat_offline_keys directory if needed.
    """
    offline_dir = os.path.expanduser("~/.chat_offline_keys")
    os.makedirs(offline_dir, exist_ok=True)
    return os.path.join(offline_dir, f"{username}.key")


def _save_offline_key_to_file(username: str, password: str, encrypted_blob: str) -> None:
    """
    Save the encrypted offline key blob to a file.
    
    Args:
        username: Username
        password: (Not used for saving, but kept for interface consistency)
        encrypted_blob: Output from encrypt_offline_key()
    """
    path = _get_offline_key_path(username)
    # Store as JSON for robustness
    data = {"username": username, "encrypted_key": encrypted_blob}
    with open(path, "w") as f:
        json.dump(data, f)
    # Set restrictive permissions
    os.chmod(path, 0o600)


def _load_offline_key_from_file(username: str, password: str):
    """
    Load and decrypt the offline key from file.
    
    Args:
        username: Username
        password: Password for decryption
        
    Returns:
        X25519PrivateKey
        
    Raises:
        FileNotFoundError: if file doesn't exist
        ValueError: if format is invalid or username mismatch
        InvalidTag: if password is wrong
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    
    path = _get_offline_key_path(username)
    with open(path, "r") as f:
        data = json.load(f)
    
    encrypted_blob = data.get("encrypted_key")
    if not encrypted_blob:
        raise ValueError("Invalid offline key file format")
    
    return decrypt_offline_key(password, encrypted_blob, username)


def _ensure_offline_key_exists(username: str, password: str):
    """
    Load offline key if exists, or generate and save a new one.
    
    Returns:
        X25519PrivateKey for offline messaging
    """
    try:
        # Try to load existing key
        private_key = _load_offline_key_from_file(username, password)
        print("  [CRYPTO] Offline key loaded from file ✓")
        return private_key
    except FileNotFoundError:
        # Generate new offline key
        print("  [CRYPTO] Generating offline key for first time...")
        private_key, pub_bytes = generate_offline_keypair()
        
        # Encrypt and save
        encrypted_blob = encrypt_offline_key(password, private_key, username)
        _save_offline_key_to_file(username, password, encrypted_blob)
        
        print("  [CRYPTO] Offline key saved to ~/.chat_offline_keys/ ✓")
        return private_key


# ---------------------------------------------------------------------------
# Key exchange helpers
# ---------------------------------------------------------------------------

def publish_my_key(sock: socket.socket) -> None:
    """
    Called immediately after a successful login.
    Publishes both ephemeral session key AND persistent offline key.
    """
    global _private_key, _offline_private_key
    _private_key, pub_bytes = generate_x25519_keypair()
    send_json(sock, {
        "type": "publish_key",
        "public_key": public_bytes_to_hex(pub_bytes),
    })
    
    # Also publish offline key if we have it
    if _offline_private_key:
        offline_pub_bytes = _offline_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        send_json(sock, {
            "type": "publish_offline_key",
            "offline_public_key": public_bytes_to_hex(offline_pub_bytes),
        })


def do_handshake(sock: socket.socket, peer_username: str) -> None:
    """
    Request a peer's public key from the server to initiate ECDH.
    The actual key derivation happens in _handle_key_response when the
    server replies asynchronously.
    """
    send_json(sock, {"type": "get_key", "username": peer_username})


def get_peer_offline_public_key(sock: socket.socket, peer_username: str) -> None:
    """
    Request a peer's offline public key from the server.
    The server will respond with offline_key_response containing the key.
    """
    send_json(sock, {"type": "get_offline_key", "username": peer_username})


def _handle_key_response(msg: dict) -> None:
    """
    Called by the receive loop when a key_response arrives.
    Derives and stores the shared AES-256-GCM key for the peer.
    Also sets them as the current peer for /msg convenience.
    """
    global _session_keys, _current_peer

    peer = msg.get("username")
    pub_hex = msg.get("public_key")
    if not peer or not pub_hex:
        return

    peer_pub_bytes = hex_to_public_bytes(pub_hex)
    secret = derive_shared_secret(_private_key, peer_pub_bytes)
    _session_keys[peer] = secret
    _current_peer = peer

    print(f"\n  [CRYPTO] Secure channel established with '{peer}' ✓")
    print(f"  [CRYPTO] You can now use: /msg {peer} <text>")
    print("  > ", end="", flush=True)


def _handle_offline_key_response(msg: dict) -> None:
    """
    Called by the receive loop when an offline_key_response arrives.
    Derives and stores the offline shared secret for the peer.
    """
    global _offline_session_keys, _offline_private_key

    peer = msg.get("username")
    pub_hex = msg.get("offline_public_key")
    if not peer or not pub_hex:
        print(f"\n  ⚠  Failed to get offline key for '{peer}'")
        print("  > ", end="", flush=True)
        return

    if not _offline_private_key:
        print(f"\n  ⚠  No offline key loaded yet")
        print("  > ", end="", flush=True)
        return

    peer_pub_bytes = hex_to_public_bytes(pub_hex)
    secret = derive_offline_shared_secret(_offline_private_key, peer_pub_bytes)
    _offline_session_keys[peer] = secret

    print(f"\n  [CRYPTO] Offline channel ready with '{peer}' ✓")
    print("  > ", end="", flush=True)


# ---------------------------------------------------------------------------
# Receive loop (background thread)
# ---------------------------------------------------------------------------

def receive_loop(sock: socket.socket, stop_event: threading.Event) -> None:
    """
    Background thread: receive and handle all messages from the server.
    """
    while not stop_event.is_set():
        try:
            msg = recv_json(sock)
            if msg is None:
                print("\n[CLIENT] Server closed the connection.")
                stop_event.set()
                break

            msg_type = msg.get("type")

            if msg_type == "message":
                sender = msg.get("from", "?")
                ciphertext_hex = msg.get("text", "")

                key = _session_keys.get(sender)
                if key is None:
                    
                    print(f"\n  ⚠  {sender} [NO SESSION KEY — run /connect {sender} first]: {ciphertext_hex}")
                else:
                    try:
                        plaintext = decrypt_message(key, ciphertext_hex)
                        print(f"\n  {sender}: {plaintext}")
                    except (InvalidTag, ValueError) as e:
                        
                        print(f"\n  ⚠  {sender} [DECRYPTION FAILED — message discarded]: {e}")

                print("  > ", end="", flush=True)

            elif msg_type == "error":
                print(f"\n  [ERROR] {msg.get('message', '')}")
                print("  > ", end="", flush=True)

            elif msg_type == "ok":
                detail = msg.get("message", "")
               
                if not detail.startswith("Delivered to"):
                    print(f"\n  [INFO] {detail}")
                    print("  > ", end="", flush=True)

            elif msg_type == "key_response":
                _handle_key_response(msg)

        except ConnectionError:
            if not stop_event.is_set():
                print("\n[CLIENT] Lost connection to server.")
                stop_event.set()
            break
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n[CLIENT] Receive error: {e}")
                stop_event.set()
            break


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def auth_flow(sock: socket.socket) -> str | None:
    """
    Synchronous register/login loop.  Returns the logged-in username or None.

    """
    print("\n  ╔════════════════════════╗")
    print("  ║     Chat E2EE v0.3     ║")
    print("  ╚════════════════════════╝\n")

    while True:
        print("  [1] Register")
        print("  [2] Login")
        print("  [q] Quit")
        choice = input("  Choice > ").strip().lower()

        if choice == "q":
            return None
        if choice not in ("1", "2"):
            print("  Invalid choice.\n")
            continue

        username = input("  Username > ").strip()
        password = getpass.getpass("  Password > ")

        if choice == "1":
            send_json(sock, {"type": "register", "username": username, "password": password})
            response = recv_json(sock)
            if response is None:
                print("  [ERROR] Server disconnected.")
                return None
            print(f"  [{response.get('type', '?').upper()}] {response.get('message', '')}\n")

        else:
            send_json(sock, {"type": "login", "username": username, "password": password})
            response = recv_json(sock)
            if response is None:
                print("  [ERROR] Server disconnected.")
                return None
            print(f"  [{response.get('type', '?').upper()}] {response.get('message', '')}\n")
            if response.get("type") == "ok":
                username = response.get("username", username)
                publish_my_key(sock)
                return username


# ---------------------------------------------------------------------------
# Chat loop
# ---------------------------------------------------------------------------

def chat_loop(sock: socket.socket, username: str) -> None:
    """
    Main interactive loop after authentication.

    """
    global _current_peer

    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_loop,
        args=(sock, stop_event),
        daemon=True,
    )
    recv_thread.start()

    print(f"  Logged in as '{username}'.")
    print("  Commands: /connect <peer>  |  /msg <peer> <text>  |  /quit\n")

    try:
        while not stop_event.is_set():
            print("  > ", end="", flush=True)
            try:
                line = input().strip()
            except EOFError:
                break

            if not line:
                continue

            # ------------------------------------------------------------------
            # /quit
            # ------------------------------------------------------------------
            if line.lower() == "/quit":
                send_json(sock, {"type": "quit"})
                stop_event.set()
                break

            # ------------------------------------------------------------------
            # /connect <peer>  — initiate ECDH handshake
            # ------------------------------------------------------------------
            if line.startswith("/connect "):
                peer = line.split(" ", 1)[1].strip()
                if not peer:
                    print("  Usage: /connect <username>")
                else:
                    do_handshake(sock, peer)
                    # Also request offline key for backup
                    get_peer_offline_public_key(sock, peer)
                continue

            # ------------------------------------------------------------------
            # /msg <peer> <text>  — send encrypted message to a specific peer
            # ------------------------------------------------------------------
            if line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("  Usage: /msg <peer> <text>")
                    continue
                peer, text = parts[1], parts[2]
                _send_encrypted(sock, peer, text)
                continue

           
            if _current_peer:
                _send_encrypted(sock, _current_peer, line)
            else:
                print("  No active peer. Use /connect <peer> first, then /msg <peer> <text>.")

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()


def _send_encrypted(sock: socket.socket, peer: str, plaintext: str) -> None:
    """
    Send encrypted message using session key if available, else offline key.
    If offline key not yet cached, request it from server.
    """
    # Try session key first (online)
    key = _session_keys.get(peer)
    if key is not None:
        ciphertext_hex = encrypt_message(key, plaintext)
        send_json(sock, {"type": "message", "to": peer, "text": ciphertext_hex})
        _message_counts[peer] = _message_counts.get(peer, 0) + 1
        
        # Check if we need to rotate
        if _message_counts[peer] >= KEY_ROTATION_THRESHOLD:
            _message_counts[peer] = 0
            _rotate_key(sock, peer)
        return
    
    # Try offline key (if cached)
    offline_key = _offline_session_keys.get(peer)
    if offline_key is not None:
        ciphertext_hex = encrypt_message(offline_key, plaintext)
        
        # Include our offline public key so recipient can decrypt
        offline_pub_bytes = _offline_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        
        send_json(sock, {
            "type": "message",
            "to": peer,
            "text": ciphertext_hex,
            "offline_public_key": public_bytes_to_hex(offline_pub_bytes),
        })
        return
    
    # No session key and no offline key — request peer's offline key
    print(f"  [INFO] No session with '{peer}'. Requesting offline key...")
    get_peer_offline_public_key(sock, peer)
        
        
def _rotate_key(sock: socket.socket, peer: str) -> None:
    """Gera um novo par de chaves e reinicia o handshake com o peer."""
    global _private_key
    _private_key, pub_bytes = generate_x25519_keypair()
    send_json(sock, {
        "type": "publish_key",
        "public_key": public_bytes_to_hex(pub_bytes),
    })
    
    do_handshake(sock, peer)
    print(f"\n  [CRYPTO] Key rotated after {KEY_ROTATION_THRESHOLD} messages with '{peer}'")

def start_client(host: str = HOST, port: int = PORT) -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"[CLIENT] Could not connect to {host}:{port}. Is the server running?")
        sys.exit(1)

    try:
        username = auth_flow(sock)
        if username is None:
            print("[CLIENT] Exiting.")
            return
        chat_loop(sock, username)
    finally:
        sock.close()
        print("[CLIENT] Connection closed.")


if __name__ == "__main__":
    start_client()