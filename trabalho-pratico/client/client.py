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

# Buffer for offline messages that arrive before _offline_private_key is loaded
_pending_offline_messages: list[dict] = []

# Flag to track if offline_private_key is loaded
_offline_key_ready = False

# Store offline messages by sender: {sender: [messages]}
_stored_offline_messages: dict[str, list[str]] = {}

# Cache peer offline public keys: {peer: hex_key}
_peer_offline_public_keys: dict[str, str] = {}

# Queue of messages waiting for offline key: {peer: [(text, is_offline_send)]}
_pending_sends: dict[str, list[tuple[str, bool]]] = {}

# Socket reference stored for use in async callbacks (e.g. _handle_offline_key_response)
_sock: socket.socket | None = None

# Tracks peers to whom the last send used the offline key — suppresses false warn
_last_sent_was_offline: set[str] = set()

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
        print("  [CRYPTO] Offline key loaded from file OK")
        return private_key
    except FileNotFoundError:
        # Generate new offline key
        print("  [CRYPTO] Generating offline key for first time...")
        private_key, pub_bytes = generate_offline_keypair()
        
        # Encrypt and save
        encrypted_blob = encrypt_offline_key(password, private_key, username)
        _save_offline_key_to_file(username, password, encrypted_blob)
        
        print("  [CRYPTO] Offline key saved to ~/.chat_offline_keys/ OK")
        return private_key


# ---------------------------------------------------------------------------
# Process buffered offline messages
# ---------------------------------------------------------------------------

def _process_pending_offline_messages() -> None:
    """
    Process any offline messages that were buffered before _offline_private_key
    was fully loaded and available.
    """
    global _pending_offline_messages, _offline_private_key
    
    if not _pending_offline_messages or not _offline_private_key:
        return
    
    pending = _pending_offline_messages[:]
    _pending_offline_messages.clear()
    
    for msg in pending:
        try:
            sender = msg["sender"]
            ciphertext_hex = msg["ciphertext_hex"]
            sender_offline_public_key = msg["sender_offline_public_key"]
            
            peer_pub_bytes = hex_to_public_bytes(sender_offline_public_key)
            offline_key = derive_offline_shared_secret(
                _offline_private_key,
                peer_pub_bytes
            )
            plaintext = decrypt_message(offline_key, ciphertext_hex)
            print(f"\n  {sender} (offline): {plaintext}")
            _store_offline_message_from_sender(sender, plaintext)
        except (InvalidTag, ValueError) as e:
            print(f"\n  [WARN]  {sender} [OFFLINE MSG DECRYPTION FAILED]: {e}")
    
    if pending:
        print("  > ", end="", flush=True)


def _sync_offline_messages(sock: socket.socket) -> None:
    """
    Request the server to deliver any pending offline messages.
    Called after offline_private_key is loaded and ready.
    """
    send_json(sock, {"type": "sync_offline_messages"})


def _check_offline_messages(sock: socket.socket) -> None:
    """
    Request list of users who have offline messages for us.
    """
    send_json(sock, {"type": "get_offline_senders"})


def _show_offline_message(sender: str) -> None:
    """
    Display all offline messages from a specific sender.
    """
    global _stored_offline_messages
    
    if sender not in _stored_offline_messages:
        print(f"  [INFO] No offline messages from '{sender}'")
        return
    
    messages = _stored_offline_messages[sender]
    print(f"\n  -- Offline messages from {sender} --")
    for i, msg in enumerate(messages, 1):
        print(f"  [{i}] {msg}")
    print(f"  ----------------------------------")
    print("  > ", end="", flush=True)


def _store_offline_message_from_sender(sender: str, plaintext: str) -> None:
    """
    Store a decrypted offline message so user can view it later with /offline.
    """
    global _stored_offline_messages
    
    if sender not in _stored_offline_messages:
        _stored_offline_messages[sender] = []
    
    _stored_offline_messages[sender].append(plaintext)


# ---------------------------------------------------------------------------
# Key exchange helpers
# ---------------------------------------------------------------------------

def publish_my_key(sock: socket.socket) -> None:
    """
    Called immediately after a successful login (before receive_loop starts).
    Publishes both ephemeral session key AND persistent offline key.
    Reads the server ACKs synchronously so they don't pollute receive_loop.
    """
    global _private_key, _offline_private_key
    _private_key, pub_bytes = generate_x25519_keypair()
    send_json(sock, {
        "type": "publish_key",
        "public_key": public_bytes_to_hex(pub_bytes),
    })
    # Read ACK synchronously — receive_loop not running yet
    ack = recv_json(sock)
    if ack and ack.get("type") != "ok":
        print(f"  [WARN] Unexpected response to publish_key: {ack}")

    # Also publish offline key
    if _offline_private_key:
        offline_pub_bytes = _offline_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        send_json(sock, {
            "type": "publish_offline_key",
            "offline_public_key": public_bytes_to_hex(offline_pub_bytes),
        })
        # Read ACK synchronously
        ack2 = recv_json(sock)
        if ack2 and ack2.get("type") != "ok":
            print(f"  [WARN] Unexpected response to publish_offline_key: {ack2}")


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

    print(f"\n  [CRYPTO] Secure channel established with '{peer}' OK")
    print(f"  [CRYPTO] You can now use: /msg {peer} <text>")
    print("  > ", end="", flush=True)


def _handle_offline_key_response(msg: dict) -> None:
    """
    Called by the receive loop when an offline_key_response arrives.
    Derives and stores the offline shared secret for the peer.
    Also processes any pending messages waiting for this key.
    """
    global _offline_session_keys, _peer_offline_public_keys, _offline_private_key, _pending_sends

    peer = msg.get("username")
    pub_hex = msg.get("offline_public_key")
    if not peer or not pub_hex:
        print(f"\n  [WARN]  Failed to get offline key for '{peer}'")
        print("  > ", end="", flush=True)
        return

    if not _offline_private_key:
        print(f"\n  [WARN]  No offline key loaded yet")
        print("  > ", end="", flush=True)
        return

    # Store the peer's offline public key
    _peer_offline_public_keys[peer] = pub_hex

    # Derive and cache the offline shared secret
    peer_pub_bytes = hex_to_public_bytes(pub_hex)
    secret = derive_offline_shared_secret(_offline_private_key, peer_pub_bytes)
    _offline_session_keys[peer] = secret

    # Process any pending sends for this peer — send directly, never re-queue
    if peer in _pending_sends:
        pending = _pending_sends.pop(peer)
        offline_pub_bytes = _offline_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        for text, _ in pending:
            ciphertext_hex = encrypt_message(secret, text)
            send_json(_sock, {
                "type": "message",
                "to": peer,
                "text": ciphertext_hex,
                "offline_public_key": public_bytes_to_hex(offline_pub_bytes),
            })
        count = len(pending)
        _last_sent_was_offline.add(peer)
        print(f"\n  [{count} offline message(s) sent to '{peer}']")

    print("  > ", end="", flush=True)


def _do_send_message(sock: socket.socket | None, peer: str, plaintext: str, force_offline: bool = False) -> bool:
    """
    Internal function to actually send a message.
    Returns True if sent, False if queued pending key.
    sock can be None if we're just processing a pending offline key.
    """
    if sock is None:
        return False

    # Try session key first (online)
    if not force_offline:
        key = _session_keys.get(peer)
        if key is not None:
            ciphertext_hex = encrypt_message(key, plaintext)
            send_json(sock, {"type": "message", "to": peer, "text": ciphertext_hex})
            _message_counts[peer] = _message_counts.get(peer, 0) + 1
            
            # Check if we need to rotate
            if _message_counts[peer] >= KEY_ROTATION_THRESHOLD:
                _message_counts[peer] = 0
                _rotate_key(sock, peer)
            print(f"\n  OK Message sent to {peer}")
            print("  > ", end="", flush=True)
            return True
    
    # Try offline key (if cached or forced)
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
        print(f"\n  OK Offline message queued for {peer} (will be delivered when they login)")
        print("  > ", end="", flush=True)
        return True
    
    # No key available - need to request it
    if force_offline or not _session_keys.get(peer):
        print(f"\n  No offline key for '{peer}'. Requesting from server...")
        # Queue the message for when key arrives
        if peer not in _pending_sends:
            _pending_sends[peer] = []
        _pending_sends[peer].append((plaintext, force_offline))
        get_peer_offline_public_key(sock, peer)
        print("  > ", end="", flush=True)
        return False
    
    return False


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
                sender_offline_public_key = msg.get("sender_offline_public_key")

                # Try session key first (online message)
                key = _session_keys.get(sender)
                if key is not None:
                    try:
                        plaintext = decrypt_message(key, ciphertext_hex)
                        print(f"\n  {sender}: {plaintext}")
                    except (InvalidTag, ValueError) as e:
                        print(f"\n  [WARN]  {sender} [DECRYPTION FAILED — message discarded]: {e}")
                else:
                    # Try offline key if sender provided their offline public key
                    if sender_offline_public_key:
                        if _offline_private_key:
                            try:
                                peer_pub_bytes = hex_to_public_bytes(sender_offline_public_key)
                                offline_key = derive_offline_shared_secret(
                                    _offline_private_key,
                                    peer_pub_bytes
                                )
                                plaintext = decrypt_message(offline_key, ciphertext_hex)
                                # Mark clearly as offline message with timestamp indicator
                                print(f"\n  [offline] {sender}: {plaintext}")
                                _store_offline_message_from_sender(sender, plaintext)
                            except (InvalidTag, ValueError) as e:
                                print(f"\n  [WARN]  {sender} [OFFLINE MSG DECRYPTION FAILED]: {e}")
                        else:
                            # Offline key not ready yet — buffer the message
                            _pending_offline_messages.append({
                                "sender": sender,
                                "ciphertext_hex": ciphertext_hex,
                                "sender_offline_public_key": sender_offline_public_key,
                            })
                            print(f"\n  [INFO] Offline message from {sender} buffered (loading offline key...)")
                    else:
                        print(f"\n  [WARN]  {sender} [NO SESSION KEY — run /connect {sender} first]: {ciphertext_hex}")

                print("  > ", end="", flush=True)

            elif msg_type == "error":
                print(f"\n  [ERROR] {msg.get('message', '')}")
                print("  > ", end="", flush=True)

            elif msg_type == "ok":
                detail = msg.get("message", "")
                # Show sync summary prominently if there were offline messages
                if detail.startswith("Synced ") and not detail.startswith("Synced 0"):
                    print(f"\n  -- {detail} above --")
                    print("  > ", end="", flush=True)
                elif detail.startswith("Message stored for"):
                    import re
                    m = re.search(r"stored for '([^']+)'", detail)
                    peer = m.group(1) if m else "?"
                    # Suppress warn if we intentionally sent via offline key (/msg_off)
                    if peer in _last_sent_was_offline:
                        _last_sent_was_offline.discard(peer)
                    else:
                        print(f"\n  [WARN] '{peer}' ficou offline. Use /msg_off {peer} <texto> para enviar mensagens offline.")
                    print("  > ", end="", flush=True)
                elif not detail.startswith("Delivered to") and not detail.startswith("Synced"):
                    print(f"\n  [INFO] {detail}")
                    print("  > ", end="", flush=True)

            elif msg_type == "key_response":
                _handle_key_response(msg)

            elif msg_type == "offline_key_response":
                _handle_offline_key_response(msg)

            elif msg_type == "offline_senders":
                senders = msg.get("senders", [])
                if senders:
                    print(f"\n  [INFO] Mensagens offline de: {', '.join(senders)}")
                    print(f"  Use: /offline <user> para as ler")
                    print("  > ", end="", flush=True)

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
    global _offline_private_key
    
    print("\n  +------------------------+")
    print("  |     Chat E2EE v0.3     |")
    print("  +------------------------+\n")

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
                
                # Load or generate offline key
                try:
                    _offline_private_key = _ensure_offline_key_exists(username, password)
                except Exception as e:
                    print(f"  [ERROR] Failed to manage offline key: {e}")
                    return None
                
                # Process any offline messages that arrived before the key was loaded
                _process_pending_offline_messages()
                
                # Sync will happen after receive_loop is active (in chat_loop_interactive)
                publish_my_key(sock)
                return username


# ---------------------------------------------------------------------------
# Chat loop
# ---------------------------------------------------------------------------

def chat_loop_interactive(sock: socket.socket, username: str, stop_event: threading.Event) -> None:
    """
    Main interactive loop after authentication.
    Uses an already-running receive_loop via stop_event.
    """
    global _current_peer, _sock
    _sock = sock  # Store globally so async callbacks (_handle_offline_key_response) can use it

    print(f"  Logged in as '{username}'.")
    print("  Commands: /connect <peer> | /msg <peer> <text> | /msg_off <peer> <text> | /offline <peer> | /quit\n")

    # Sync offline messages now that receive_loop is active
    import time
    time.sleep(0.5)  # Small delay for receive_loop to initialize
    _sync_offline_messages(sock)

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

            # ------------------------------------------------------------------
            # /msg_off <peer> <text>  — send message even without active session
            # Uses persistent offline keys; works even if peer was never online with us.
            # ------------------------------------------------------------------
            if line.startswith("/msg_off "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("  Usage: /msg_off <peer> <text>")
                    continue
                peer, text = parts[1], parts[2]
                _send_offline_forced(sock, peer, text)
                continue

            # ------------------------------------------------------------------
            # /offline <peer>  — view offline messages from a peer
            # ------------------------------------------------------------------
            if line.startswith("/offline "):
                peer = line.split(" ", 1)[1].strip()
                if not peer:
                    print("  Usage: /offline <peer>")
                else:
                    _show_offline_message(peer)
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
    global _last_sent_was_offline
    _last_sent_was_offline.discard(peer)  # Regular /msg — mark as session-key send

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
        
        
def _send_offline_forced(sock: socket.socket, peer: str, plaintext: str) -> None:
    """
    Send a message using only the offline key channel.
    Works even without an active session (i.e. peer was never online with us).

    If the peer's offline key is already cached, sends immediately.
    Otherwise, enqueues the message and requests the key from the server —
    it will be sent once in _handle_offline_key_response, never re-queued.
    """
    offline_key = _offline_session_keys.get(peer)
    if offline_key is not None:
        # Key already cached — send immediately
        ciphertext_hex = encrypt_message(offline_key, plaintext)
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
        _last_sent_was_offline.add(peer)
        print(f"  [OK] Offline message sent to '{peer}'")
        return

    # Key not cached — enqueue once and request it; handler will send without re-queuing
    if peer not in _pending_sends:
        _pending_sends[peer] = []
    _pending_sends[peer].append((plaintext, True))
    print(f"  [INFO] Fetching offline key for '{peer}', message queued...")
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
        
        # NOW start receive loop after auth is complete
        stop_event = threading.Event()
        recv_thread = threading.Thread(
            target=receive_loop,
            args=(sock, stop_event),
            daemon=True,
        )
        recv_thread.start()
        
        # Continue with chat loop
        chat_loop_interactive(sock, username, stop_event)
    finally:
        sock.close()
        print("[CLIENT] Connection closed.")


if __name__ == "__main__":
    start_client()