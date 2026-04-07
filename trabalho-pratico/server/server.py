import socket
import threading
import sys
import os

# Allow importing from the common/ package regardless of where you run from
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.protocol import send_message, recv_message



HOST = "0.0.0.0" 
PORT = 9000


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """
    Handle a single connected client in its own thread.

    This function runs for the entire lifetime of one client connection.
    When the client disconnects, the thread ends and resources are released.
    """
    print(f"[SERVER] Client connected: {addr}")

    try:
        while True:
            message = recv_message(conn)

            if message is None:
                # Client closed the connection cleanly
                print(f"[SERVER] Client disconnected: {addr}")
                break

            print(f"[SERVER] Received from {addr}: {message!r}")

            # Echo the message back with a label
            echo = f"[ECHO from server] {message}"
            send_message(conn, echo)

    except ConnectionError as e:
        print(f"[SERVER] Connection error with {addr}: {e}")
    except Exception as e:
        print(f"[SERVER] Unexpected error with {addr}: {e}")
    finally:
        conn.close()


def start_server(host: str = HOST, port: int = PORT) -> None:
    """
    Start the TCP server and accept clients in a loop.

    Each new connection spawns a daemon thread. Daemon threads are
    automatically killed when the main program exits, which is convenient
    during development.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        # Avoids "Address already in use" when restarting quickly
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen()

        print(f"[SERVER] Listening on {host}:{port}")
        print(f"[SERVER] Waiting for connections... (Ctrl+C to stop)")

        try:
            while True:
                conn, addr = server_sock.accept()
                # Spawn a new thread for this client
                thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                thread.start()
                print(f"[SERVER] Active connections: {threading.active_count() - 1}")

        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")


if __name__ == "__main__":
    start_server()