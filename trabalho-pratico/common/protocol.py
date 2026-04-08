"""
common/protocol.py — Message framing for the chat system.

WHY THIS EXISTS:
  TCP is a stream protocol — it has no concept of "message boundaries".
  If the server sends "Hello" and "World" back-to-back, the client might
  receive "HelloWorld" or "Hel" + "loWorld" depending on buffering.

  Solution: length-prefix framing.
  Every message is sent as:
    [4 bytes: length of payload as big-endian uint32] [payload bytes]

  This makes it trivial to know exactly how many bytes to read for each message.
  This framing layer will remain useful in all future phases (even with encryption,
  you'll still need to know how many bytes the ciphertext occupies).
"""

import json
import socket
import struct

# Header is always 4 bytes (unsigned int, big-endian) = max message size ~4GB
HEADER_SIZE = 4
HEADER_FORMAT = "!I"  # network byte order (big-endian), unsigned int


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


import json


def send_json(sock: socket.socket, data: dict) -> None:
    """
    Serialize a dict to JSON and send it as a framed message.

    WHY JSON: We need structured messages now that the protocol has multiple
    message types (register, login, chat, error...). JSON is human-readable
    for debugging, and trivially extensible — adding a new field to a message
    type doesn't break anything.

    All higher-level code should use send_json/recv_json, NOT send_message/recv_message
    directly. The raw string functions stay for internal use and testing.
    """
    send_message(sock, json.dumps(data))


def recv_json(sock: socket.socket) -> dict | None:
    """
    Receive a framed message and deserialize it from JSON.

    Returns:
        A dict, or None if the connection was closed cleanly.

    Raises:
        ConnectionError: if the connection breaks mid-message.
        ValueError: if the received bytes are not valid JSON.
    """
    raw = recv_message(sock)
    if raw is None:
        return None
    return json.loads(raw)


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