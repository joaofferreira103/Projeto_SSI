"""
server/server.py — Multi-threaded chat server.

"""

import socket
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.protocol import send_json, recv_json
from database import Database


HOST = "0.0.0.0"
PORT = 9000

db = Database()

# {username: socket} — protected by a lock because multiple threads write it.
connected_users: dict[str, socket.socket] = {}
connected_users_lock = threading.Lock()


def _deliver(recipient: str, envelope: dict) -> bool:
    """
    Try to deliver a JSON envelope to a connected user.

    Returns True if delivered, False if the user is offline.
    If offline and message type is 'message', stores it for later delivery.
    """
    with connected_users_lock:
        sock = connected_users.get(recipient)
    if sock is None:
        # If it's a message and recipient is offline, store for later
        if envelope.get("type") == "message":
            sender = envelope.get("from")
            ciphertext = envelope.get("text")
            sender_offline_key = envelope.get("sender_offline_public_key")
            if sender and ciphertext:
                db.store_offline_message(
                    recipient,
                    sender,
                    ciphertext,
                    sender_offline_key,
                )
        return False
    try:
        send_json(sock, envelope)
        return True
    except Exception:
        return False


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """
    Handle one client connection through its full lifecycle:
      Phase A — Authentication (register / login, repeatable until success)
      Phase B — Authenticated chat (message routing, key exchange helpers)
    """
    print(f"[SERVER] Client connected: {addr}")
    username = None

    try:
        # ------------------------------------------------------------------
        # Phase A: Authentication
        # ------------------------------------------------------------------
        while username is None:
            msg = recv_json(conn)
            if msg is None:
                print(f"[SERVER] {addr} disconnected before authenticating")
                return

            msg_type = msg.get("type")

            if msg_type == "register":
                ok, reason = db.register_user(
                    msg.get("username", ""),
                    msg.get("password", ""),
                )
                send_json(conn, {"type": "ok" if ok else "error", "message": reason})

            elif msg_type == "login":
                ok, reason = db.verify_user(
                    msg.get("username", ""),
                    msg.get("password", ""),
                )
                if ok:
                    username = msg["username"]
                    with connected_users_lock:
                        connected_users[username] = conn
                    send_json(conn, {"type": "ok", "message": reason, "username": username})
                    print(f"[SERVER] '{username}' logged in from {addr}")
                    
                    # Deliver any pending offline messages
                    offline_msgs = db.get_offline_messages(username)
                    for offline_msg in offline_msgs:
                        send_json(conn, {
                            "type": "message",
                            "from": offline_msg["sender"],
                            "text": offline_msg["ciphertext_hex"],
                            "sender_offline_public_key": offline_msg["sender_offline_public_key"],
                        })
                    
                    # Delete offline messages after delivery
                    if offline_msgs:
                        db.delete_offline_messages(username)
                        print(f"[SERVER] Delivered {len(offline_msgs)} offline message(s) to '{username}'")
                else:
                    send_json(conn, {"type": "error", "message": reason})

            else:
                send_json(conn, {
                    "type": "error",
                    "message": f"Unknown command '{msg_type}'. Please register or login first.",
                })

        # ------------------------------------------------------------------
        # Phase B: Authenticated chat
        # ------------------------------------------------------------------
        while True:
            msg = recv_json(conn)
            if msg is None:
                print(f"[SERVER] '{username}' disconnected")
                break

            msg_type = msg.get("type")

            if msg_type == "message":
               
                recipient = msg.get("to", "")
                ciphertext = msg.get("text", "")
                sender_offline_public_key = msg.get("offline_public_key")  # New field

                if not recipient:
                    send_json(conn, {"type": "error", "message": "Missing 'to' field"})
                    continue

                if recipient == username:
                    send_json(conn, {"type": "error", "message": "Cannot send a message to yourself"})
                    continue

                # Build envelope with optional offline public key
                envelope = {
                    "type": "message",
                    "from": username,
                    "text": ciphertext,  
                }
                if sender_offline_public_key:
                    envelope["sender_offline_public_key"] = sender_offline_public_key

                delivered = _deliver(recipient, envelope)

                if not delivered:
                    send_json(conn, {
                        "type": "ok",
                        "message": f"Message stored for '{recipient}' (offline)",
                    })
                else:
                  
                    send_json(conn, {"type": "ok", "message": f"Delivered to '{recipient}'"})

            elif msg_type == "publish_key":
                pub_hex = msg.get("public_key", "")
                if pub_hex:
                    db.store_public_key(username, pub_hex)
                    send_json(conn, {"type": "ok", "message": "Public key stored"})
                else:
                    send_json(conn, {"type": "error", "message": "Missing public_key field"})

            elif msg_type == "publish_offline_key":
                offline_pub_hex = msg.get("offline_public_key", "")
                if offline_pub_hex:
                    db.store_offline_public_key(username, offline_pub_hex)
                    send_json(conn, {"type": "ok", "message": "Offline public key stored"})
                else:
                    send_json(conn, {"type": "error", "message": "Missing offline_public_key field"})

            elif msg_type == "get_key":
                target = msg.get("username", "")
                pub_hex = db.get_public_key(target)
                if pub_hex:
                    send_json(conn, {
                        "type": "key_response",
                        "username": target,
                        "public_key": pub_hex,
                    })
                    my_pub_hex = db.get_public_key(username)
                    if my_pub_hex:
                        _deliver(target, {
                            "type": "key_response",
                            "username": username,
                            "public_key": my_pub_hex,
                        })
                else:
                    send_json(conn, {
                        "type": "error",
                        "message": f"No public key found for '{target}' (offline?)",
                    })

            elif msg_type == "get_offline_key":
                target = msg.get("username", "")
                offline_pub_hex = db.get_offline_public_key(target)
                if offline_pub_hex:
                    send_json(conn, {
                        "type": "offline_key_response",
                        "username": target,
                        "offline_public_key": offline_pub_hex,
                    })
                else:
                    send_json(conn, {
                        "type": "error",
                        "message": f"No offline public key found for '{target}'",
                    })

            elif msg_type == "quit":
                send_json(conn, {"type": "ok", "message": "Goodbye!"})
                break

            else:
                send_json(conn, {
                    "type": "error",
                    "message": f"Unknown message type: '{msg_type}'",
                })

    except ConnectionError as e:
        print(f"[SERVER] Connection error with {addr}: {e}")
    except Exception as e:
        print(f"[SERVER] Unexpected error with {addr}: {e}")
    finally:
        if username:
            with connected_users_lock:
                connected_users.pop(username, None)
            db.remove_public_key(username)
            print(f"[SERVER] '{username}' removed from active users")
        conn.close()


def start_server(host: str = HOST, port: int = PORT) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen()
        print(f"[SERVER] Listening on {host}:{port}")
        try:
            while True:
                conn, addr = server_sock.accept()
                threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")
        finally:
            db.close()


if __name__ == "__main__":
    start_server()