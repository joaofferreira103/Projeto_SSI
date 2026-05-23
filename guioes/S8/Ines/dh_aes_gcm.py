# Questão 1: Implementação do protocolo Diffie-Hellman com AES-GCM e suporte a PFS (Perfect Forward Secrecy)
# Este programa troca várias mensagens utilizando chaves derivadas únicas para cada mensagem.

from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Parâmetros fixos (p e g)
p = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
    "8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
    "0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
    "1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
    "F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6"
    "955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)
g = 2

# Geração dos parâmetros DH
parameters = dh.DHParameterNumbers(p, g).parameters()

def derive_key(shared_key):
    # Deriva uma chave simétrica usando HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dh key exchange'
    )
    return hkdf.derive(shared_key)

def alice_process(conn):
    # Gera a chave privada e pública de Alice
    alice_private_key = parameters.generate_private_key()
    alice_public_key = alice_private_key.public_key()

    # Serializa a chave pública de Alice para envio
    alice_public_bytes = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 1. Alice → Bob: Envia a chave pública
    conn.send(alice_public_bytes)

    # 2. Bob → Alice: Recebe a chave pública de Bob
    bob_public_bytes = conn.recv()
    bob_public_key = serialization.load_pem_public_key(bob_public_bytes)

    # 3. Calcula a chave secreta compartilhada
    shared_key = alice_private_key.exchange(bob_public_key)
    symmetric_key = derive_key(shared_key)
    print("Chave secreta derivada de Alice:", symmetric_key.hex())

    # Envia uma mensagem confidencial para Bob
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)  # Gera um nonce aleatório
    plaintext = b"Mensagem confidencial de Alice para Bob"
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    conn.send((nonce, ciphertext))

def bob_process(conn):
    # Gera a chave privada e pública de Bob
    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()

    # 1. Alice → Bob: Recebe a chave pública de Alice
    alice_public_bytes = conn.recv()
    alice_public_key = serialization.load_pem_public_key(alice_public_bytes)

    # Serializa a chave pública de Bob para envio
    bob_public_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 2. Bob → Alice: Envia a chave pública
    conn.send(bob_public_bytes)

    # 3. Calcula a chave secreta compartilhada
    shared_key = bob_private_key.exchange(alice_public_key)
    symmetric_key = derive_key(shared_key)
    print("Chave secreta derivada de Bob:", symmetric_key.hex())

    # Recebe a mensagem confidencial de Alice
    nonce, ciphertext = conn.recv()
    aesgcm = AESGCM(symmetric_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    print("Mensagem recebida por Bob:", plaintext.decode())

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start()
    p2.start()
    p1.join()
    p2.join()