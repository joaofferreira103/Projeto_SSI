import socket
import threading
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.protocol import send_json, recv_json
from database import Database

HOST = "0.0.0.0"
PORT = 9000

# Shared database instance — one per server process, used by all threads
db = Database()

# Registry of currently connected authenticated users: {username: socket}
# Protected by a lock because multiple threads read/write it concurrently
connected_users: dict = {}
connected_users_lock = threading.Lock()


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """
    Handle one client connection through its full lifecycle:
      1. Authentication phase (register or login)
      2. Chat phase (only reachable after successful login)
    """
    print(f"[SERVER] Client connected: {addr}")
    username = None

    try:
        # Phase A: Authentication loop
        # The client MUST successfully login before doing anything else.
        # We loop to allow multiple attempts (e.g., wrong password -> try again).
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
                else:
                    send_json(conn, {"type": "error", "message": reason})

            else:
                send_json(conn, {
                    "type": "error",
                    "message": f"Unknown command '{msg_type}'. Please register or login first."
                })

        # Phase B: Authenticated chat loop
        while True:
            msg = recv_json(conn)
            if msg is None:
                print(f"[SERVER] '{username}' disconnected")
                break

            msg_type = msg.get("type")

            if msg_type == "message":
                text = msg.get("text", "")
                print(f"[SERVER] Message from '{username}': {text!r}")
                # Phase 2: still echoing. Phase 3 will route to a recipient.
                send_json(conn, {
                    "type": "message",
                    "from": username,
                    "text": f"[echo] {text}",
                })

            elif msg_type == "quit":
                send_json(conn, {"type": "ok", "message": "Goodbye!"})
                break

            else:
                send_json(conn, {
                    "type": "error",
                    "message": f"Unknown message type: '{msg_type}'"
                })

    except ConnectionError as e:
        print(f"[SERVER] Connection error with {addr}: {e}")
    except Exception as e:
        print(f"[SERVER] Unexpected error with {addr}: {e}")
    finally:
        if username:
            with connected_users_lock:
                connected_users.pop(username, None)
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
                thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")
        finally:
            db.close()


if __name__ == "__main__":
    start_server()