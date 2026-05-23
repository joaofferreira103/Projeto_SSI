#!/usr/bin/env python3
import struct
import sys
from pathlib import Path

KEY_SIZE = 32

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


class SHA256:
    def __init__(self, h=None, message_len=0):
        if h is None:
            self.h = [
                0x6A09E667,
                0xBB67AE85,
                0x3C6EF372,
                0xA54FF53A,
                0x510E527F,
                0x9B05688C,
                0x1F83D9AB,
                0x5BE0CD19,
            ]
        else:
            self.h = list(h)
        self.message_len = message_len
        self.buffer = b""

    def _process_block(self, block: bytes) -> None:
        w = list(struct.unpack(">16I", block)) + [0] * 48
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + s1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def update(self, data: bytes) -> None:
        self.message_len += len(data)
        self.buffer += data
        while len(self.buffer) >= 64:
            self._process_block(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self) -> bytes:
        h_copy = self.h[:]
        buf_copy = self.buffer
        msg_len_copy = self.message_len

        total_bits = msg_len_copy * 8
        pad = b"\x80"
        pad += b"\x00" * ((56 - (msg_len_copy + 1) % 64) % 64)
        pad += struct.pack(">Q", total_bits)

        self.update(pad)
        out = b"".join(struct.pack(">I", x) for x in self.h)

        self.h = h_copy
        self.buffer = buf_copy
        self.message_len = msg_len_copy
        return out


def sha256_padding(message_len_bytes: int) -> bytes:
    total_bits = message_len_bytes * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (message_len_bytes + 1) % 64) % 64)
    pad += struct.pack(">Q", total_bits)
    return pad


def forge_mac(original_msg: bytes, original_mac_hex: str, extension: bytes):
    original_mac_hex = original_mac_hex.strip().lower()
    if len(original_mac_hex) != 64:
        raise ValueError("MAC original inválido: deve ter 64 hex chars")

    h = list(struct.unpack(">8I", bytes.fromhex(original_mac_hex)))

    base_len = KEY_SIZE + len(original_msg)
    glue = sha256_padding(base_len)

    forged_msg = original_msg + glue + extension

    processed_before_ext = base_len + len(glue)
    sha = SHA256(h=h, message_len=processed_before_ext)
    sha.update(extension)
    forged_mac = sha.digest().hex()

    return forged_msg, forged_mac


def usage() -> None:
    print("Uso: mac_sha256_attack.py <fich> <ext>")


def main() -> int:
    if len(sys.argv) != 3:
        usage()
        return 1

    fich = sys.argv[1]
    ext = sys.argv[2].encode("utf-8")

    try:
        original_msg = Path(fich).read_bytes()
        original_mac = Path(f"{fich}.mac").read_text(encoding="ascii")
    except FileNotFoundError as err:
        print(f"Erro: ficheiro não encontrado: {err.filename}", file=sys.stderr)
        return 1

    try:
        forged_msg, forged_mac = forge_mac(original_msg, original_mac, ext)
    except ValueError as err:
        print(f"Erro: {err}", file=sys.stderr)
        return 1

    Path(f"{fich}.ext").write_bytes(forged_msg)
    Path(f"{fich}.ext.mac").write_text(forged_mac, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
