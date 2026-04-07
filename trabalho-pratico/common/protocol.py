import socket
import struct

# Header is always 4 bytes, max message size ~4GB
HEADER_SIZE = 4
HEADER_FORMAT = "!I" 


def send_message(sock: socket.socket, message: str) -> None:
    """
    Encode and send a framed message over the socket.

    Args:
        sock: The connected socket to send through.
        message: The plaintext string to send.

    Future phases: this is where you'd encrypt `message` before framing.
    """
    payload = message.encode("utf-8")
    header = struct.pack(HEADER_FORMAT, len(payload))
    # sendall ensures the entire buffer is sent, even if the OS splits it
    sock.sendall(header + payload)


def recv_message(sock: socket.socket) -> str | None:
    """
    Receive and decode a framed message from the socket.

    Returns:
        The decoded string, or None if the connection was closed cleanly.

    Raises:
        ConnectionError: if the connection is broken mid-message.

    Future phases: this is where you'd decrypt after receiving the raw bytes.
    """
    # Step 1: read exactly HEADER_SIZE bytes to learn payload length
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None  # connection closed before any data

    (payload_length,) = struct.unpack(HEADER_FORMAT, header)

    # Step 2: read exactly payload_length bytes
    payload = _recv_exact(sock, payload_length)
    if payload is None:
        raise ConnectionError("Connection closed mid-message")

    return payload.decode("utf-8")


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """
    Read exactly n bytes from the socket, blocking until done.
    Returns None if the connection is closed before any byte is received.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if len(buf) == 0:
                return None  # clean close
            raise ConnectionError(f"Expected {n} bytes, got {len(buf)}")
        buf += chunk
    return buf