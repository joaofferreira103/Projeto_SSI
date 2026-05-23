import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def setup(fkey):
    # ChaCha20 requer uma chave de 32 bytes (256 bits)
    key = os.urandom(32)
    with open(fkey, 'wb') as f:
        f.write(key)
    print(f"Chave gerada com sucesso em: {fkey}")

def encrypt(fich, fkey):
    with open(fkey, 'rb') as kf:
        key = kf.read()
    
    with open(fich, 'rb') as f:
        plaintext = f.read()

    # Gerar um NONCE aleatório de 16 bytes
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None) # Cifras sequenciais como ChaCha20 não usam 'mode'
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    # Gravar NONCE + Criptograma no ficheiro .enc
    with open(fich + ".enc", "wb") as f_enc:
        f_enc.write(nonce + ciphertext)
    print(f"Ficheiro cifrado: {fich}.enc")
    
def decrypt(fich, fkey):
    # 1. Ler a chave do ficheiro
    with open(fkey, 'rb') as kf:
        key = kf.read()
    
    # 2. Ler o conteúdo do ficheiro cifrado
    with open(fich, 'rb') as f:
        content = f.read()

    # 3. Separar o NONCE do Criptograma
    nonce = content[:16]
    ciphertext = content[16:]

    # 4. Configurar a cifra com os mesmos parâmetros
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    
    # 5. Decifrar (o processo é idêntico ao de cifrar devido ao XOR)
    plaintext = decryptor.update(ciphertext)

    # 6. Gravar o resultado num ficheiro .dec [cite: 86]
    with open(fich + ".dec", "wb") as f_dec:
        f_dec.write(plaintext)
    
    print(f"Ficheiro decifrado com sucesso: {fich}.dec")

