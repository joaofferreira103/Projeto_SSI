from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """
    Gera um par de chaves X25519 efémero.

    Retorna:
        (private_key, public_key_bytes) — a chave privada fica em memória,
        os bytes da pública são serializados em formato Raw (32 bytes)
        prontos para enviar pela rede.
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_bytes: bytes,
    info: bytes = b"chat-e2ee-v1",
) -> bytes:
    """
    Args:
        private_key: chave privada X25519 local (gerada por generate_x25519_keypair)
        peer_public_bytes: 32 bytes Raw da chave pública do outro utilizador
        info: contexto do protocolo — garante que o mesmo ECDH não produz
              a mesma chave em protocolos distintos

    Retorna:
        32 bytes prontos a usar como chave AES-256 (na fase seguinte).

    """
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    raw_secret = private_key.exchange(peer_public_key)

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,       # salt opcional; na fase seguinte podes adicionar
        info=info,
        backend=default_backend(),
    ).derive(raw_secret)

    return derived


def public_bytes_to_hex(public_bytes: bytes) -> str:
    """Serializa bytes de chave pública para hex (para envio em JSON)."""
    return public_bytes.hex()


def hex_to_public_bytes(hex_str: str) -> bytes:
    """Desserializa hex recebido da rede para bytes de chave pública."""
    return bytes.fromhex(hex_str)