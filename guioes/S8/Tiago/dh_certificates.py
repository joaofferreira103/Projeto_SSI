# Questão 2: Implementação do protocolo Diffie-Hellman autenticado com certificados X.509
# Este programa utiliza certificados para autenticar as chaves públicas e proteger contra ataques MitM.

from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
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

parameters = dh.DHParameterNumbers(p, g).parameters()

def derive_key(shared_key, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_key)

def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        return load_pem_x509_certificate(cert_file.read())

def verify_certificate(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        SHA256()
    )

def alice_process(conn):
    alice_private_key = parameters.generate_private_key()
    alice_public_key = alice_private_key.public_key()

    alice_cert = load_certificate("Alice.crt")
    ca_cert = load_certificate("CA.crt")
    verify_certificate(alice_cert, ca_cert)

    alice_public_bytes = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(alice_public_bytes)

    bob_public_bytes = conn.recv()
    bob_cert = load_certificate("Bob.crt")
    verify_certificate(bob_cert, ca_cert)

    bob_public_key = serialization.load_pem_public_key(bob_public_bytes)
    shared_key = alice_private_key.exchange(bob_public_key)

    # Troca de várias mensagens com diferentes chaves derivadas
    for i in range(3):
        info = f"message-{i}".encode()
        symmetric_key = derive_key(shared_key, info)
        print(f"Chave derivada para mensagem {i} (Alice):", symmetric_key.hex())

        aesgcm = AESGCM(symmetric_key)
        nonce = os.urandom(12)
        plaintext = f"Mensagem {i} de Alice para Bob".encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        conn.send((nonce, ciphertext))

def bob_process(conn):
    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()

    bob_cert = load_certificate("Bob.crt")
    ca_cert = load_certificate("CA.crt")
    verify_certificate(bob_cert, ca_cert)

    alice_public_bytes = conn.recv()
    alice_cert = load_certificate("Alice.crt")
    verify_certificate(alice_cert, ca_cert)

    alice_public_key = serialization.load_pem_public_key(alice_public_bytes)
    bob_public_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(bob_public_bytes)

    shared_key = bob_private_key.exchange(alice_public_key)

    # Troca de várias mensagens com diferentes chaves derivadas
    for i in range(3):
        info = f"message-{i}".encode()
        symmetric_key = derive_key(shared_key, info)
        print(f"Chave derivada para mensagem {i} (Bob):", symmetric_key.hex())

        nonce, ciphertext = conn.recv()
        aesgcm = AESGCM(symmetric_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print(f"Mensagem recebida por Bob (mensagem {i}):", plaintext.decode())

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start()
    p2.start()
    p1.join()
    p2.join()