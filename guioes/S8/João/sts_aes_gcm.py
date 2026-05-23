# Questão 3: Implementação do protocolo Station-to-Station (STS)
# Este programa adapta o Diffie-Hellman para incluir assinaturas e validação de certificados.

from multiprocessing import Process, Pipe
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
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
        hashes.SHA256()
    )

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

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

    bob_data = conn.recv()
    bob_public_bytes, bob_signature = unpair(bob_data)

    bob_cert = load_certificate("Bob.crt")
    verify_certificate(bob_cert, ca_cert)

    bob_public_key = serialization.load_pem_public_key(bob_public_bytes)
    bob_cert.public_key().verify(
        bob_signature,
        mkpair(bob_public_bytes, alice_public_bytes),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    shared_key = alice_private_key.exchange(bob_public_key)

    alice_signature = alice_cert.private_key().sign(
        mkpair(alice_public_bytes, bob_public_bytes),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    conn.send(alice_signature)

    symmetric_key = derive_key(shared_key, b"Station-to-Station")
    print("Chave secreta derivada de Alice:", symmetric_key.hex())

def bob_process(conn):
    bob_private_key = parameters.generate_private_key()
    bob_public_key = bob_private_key.public_key()

    bob_cert = load_certificate("Bob.crt")
    ca_cert = load_certificate("CA.crt")
    verify_certificate(bob_cert, ca_cert)

    alice_public_bytes = conn.recv()

    alice_cert = load_certificate("Alice.crt")
    verify_certificate(alice_cert, ca_cert)

    bob_public_bytes = bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    bob_signature = bob_cert.private_key().sign(
        mkpair(bob_public_bytes, alice_public_bytes),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    conn.send(mkpair(bob_public_bytes, bob_signature))

    alice_signature = conn.recv()
    alice_cert.public_key().verify(
        alice_signature,
        mkpair(alice_public_bytes, bob_public_bytes),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    shared_key = bob_private_key.exchange(serialization.load_pem_public_key(alice_public_bytes))
    symmetric_key = derive_key(shared_key, b"Station-to-Station")
    print("Chave secreta derivada de Bob:", symmetric_key.hex())

if __name__ == '__main__':
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start()
    p2.start()
    p1.join()
    p2.join()