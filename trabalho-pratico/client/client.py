import socket
import threading
import sys
import os
import getpass

# Ensure project root is importable when running this file directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.protocol import send_json, recv_json
from common.crypto import (
    generate_x25519_keypair,
    derive_shared_secret,
    public_bytes_to_hex,
    hex_to_public_bytes,
)

HOST = "127.0.0.1"
PORT = 9000

# Variável de estado por sessão
_private_key = None        # chave privada efémera desta sessão
_session_keys: dict = {}   # {username: bytes} — segredo derivado por par



def publish_my_key(sock: socket.socket) -> None:
    """
    Gera par efémero e publica a chave pública no servidor.
    Chamado imediatamente após login bem-sucedido.
    """
    global _private_key
    _private_key, pub_bytes = generate_x25519_keypair()
    send_json(sock, {
        "type": "publish_key",
        "public_key": public_bytes_to_hex(pub_bytes),
    })
    # A resposta ok/error é tratada pelo receive_loop normal

def do_handshake(sock: socket.socket, peer_username: str) -> None:
    """
    Inicia handshake com outro utilizador: pede a chave pública dele
    ao servidor e deriva o segredo partilhado.

    Uso: o utilizador escreve /connect bob no chat.
    """
    send_json(sock, {"type": "get_key", "username": peer_username})
    # A resposta chega assincronamente no receive_loop

def _handle_key_response(msg: dict) -> None:
    """
    Chamado pelo receive_loop quando chega um key_response.
    Deriva e armazena o segredo partilhado com o peer.
    """
    global _session_keys
    peer = msg.get("username")
    pub_hex = msg.get("public_key")
    if not peer or not pub_hex:
        return

    peer_pub_bytes = hex_to_public_bytes(pub_hex)
    secret = derive_shared_secret(_private_key, peer_pub_bytes)
    _session_keys[peer] = secret
    print(f"\n  [CRYPTO] Canal seguro estabelecido com '{peer}' ✓")
    print("  > ", end="", flush=True)


def receive_loop(sock: socket.socket, stop_event: threading.Event) -> None:
    """
    Background thread: receive and display messages from the server.
    Handles all message types that can arrive during the chat phase.
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
                text = msg.get("text", "")
                print(f"\n  {sender}: {text}")
                print("  > ", end="", flush=True)

            elif msg_type == "error":
                print(f"\n  [ERROR] {msg.get('message', '')}")
                print("  > ", end="", flush=True)

            elif msg_type == "ok":
                # Informational — e.g., "Goodbye!"
                print(f"\n  [INFO] {msg.get('message', '')}")
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


def auth_flow(sock: socket.socket) -> str | None:
    """
    Handle the register/login sequence before entering the chat loop.

    Returns the logged-in username on success, or None if the user quits.

    Design note: this is a blocking, synchronous function — no background
    thread during auth, because we need strict request/response ordering
    (send login -> wait for ok/error -> proceed or retry).
    The receive thread is only started AFTER this succeeds.
    """
    print("\n  ╔════════════════════════╗")
    print("  ║     Chat E2EE v0.2     ║")
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
        # getpass hides the password while typing (no echo on terminal)
        password = getpass.getpass("  Password > ")

        if choice == "1":
            send_json(sock, {"type": "register", "username": username, "password": password})
            response = recv_json(sock)
            if response is None:
                print("  [ERROR] Server disconnected.")
                return None
            print(f"  [{response.get('type', '?').upper()}] {response.get('message', '')}\n")
            # After registering, loop back so the user can login

        else:  # choice == "2"
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
            # On error, loop back and let user try again


def chat_loop(sock: socket.socket, username: str) -> None:
    """
    Main chat loop after authentication.
    Starts the background receive thread, then reads user input.
    """
    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_loop,
        args=(sock, stop_event),
        daemon=True,
    )
    recv_thread.start()

    print(f"  Logged in as '{username}'. Type /quit to exit.\n")

    try:
        while not stop_event.is_set():
            print("  > ", end="", flush=True)
            try:
                line = input().strip()
            except EOFError:
                break

            if not line:
                continue

            if line.lower() == "/quit":
                send_json(sock, {"type": "quit"})
                stop_event.set()
                break
            if line.startswith("/connect "):
                peer = line.split(" ", 1)[1].strip()
                do_handshake(sock, peer)
        

            send_json(sock, {"type": "message", "text": line})

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()


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