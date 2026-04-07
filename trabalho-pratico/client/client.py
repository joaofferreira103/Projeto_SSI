import socket
import threading
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.protocol import send_message, recv_message

HOST = "127.0.0.1"
PORT = 9000


def receive_loop(sock: socket.socket, stop_event: threading.Event) -> None:
    """
    Background thread: continuously receive and print messages from the server.

    Uses a stop_event so the main thread can signal this thread to exit
    gracefully (e.g., when the user types 'quit').
    """
    while not stop_event.is_set():
        try:
            message = recv_message(sock)
            if message is None:
                print("\n[CLIENT] Server closed the connection.")
                stop_event.set()
                break
            # Print received message, then re-display the prompt
            print(f"\n{message}")
            print("You > ", end="", flush=True)
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


def start_client(host: str = HOST, port: int = PORT) -> None:
    """
    Connect to the server and enter the interactive command loop.

    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"[CLIENT] Connected to {host}:{port}")
        print("[CLIENT] Type a message and press Enter. Type 'quit' to exit.\n")
    except ConnectionRefusedError:
        print(f"[CLIENT] Could not connect to {host}:{port}. Is the server running?")
        sys.exit(1)

    stop_event = threading.Event()

    # Start background receiver thread
    recv_thread = threading.Thread(
        target=receive_loop,
        args=(sock, stop_event),
        daemon=True,
    )
    recv_thread.start()

    try:
        while not stop_event.is_set():
            print("You > ", end="", flush=True)
            try:
                line = input()
            except EOFError:
                # Happens when stdin is closed (e.g., piped input ends)
                break

            line = line.strip()

            if not line:
                continue  # ignore empty input

            if line.lower() in ("quit", "exit"):
                print("[CLIENT] Disconnecting...")
                stop_event.set()
                break

            try:
                send_message(sock, line)
            except ConnectionError:
                print("[CLIENT] Failed to send. Connection lost.")
                stop_event.set()
                break

    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupted.")
    finally:
        stop_event.set()
        sock.close()
        print("[CLIENT] Connection closed.")


if __name__ == "__main__":
    start_client()