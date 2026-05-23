import os
import sys
import getpass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


AES_KEY_SIZE = 32      # 256-bit key for AES-CTR
MAC_KEY_SIZE = 32      # 256-bit key for HMAC-SHA256
KDF_KEY_SIZE = AES_KEY_SIZE + MAC_KEY_SIZE
NONCE_SIZE = 16        # AES block size (CTR nonce/initial counter)
SALT_SIZE = 16         # 128-bit salt for PBKDF2
TAG_SIZE = 32          # HMAC-SHA256 output size
PBKDF2_ITERATIONS = 480_000


def derive_keys(passphrase: bytes, salt: bytes) -> tuple[bytes, bytes]:
	#Deriva duas chaves (cifra e MAC) a partir de pass-phrase e salt via PBKDF2.
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=KDF_KEY_SIZE,
		salt=salt,
		iterations=PBKDF2_ITERATIONS,
	)
	key_material = kdf.derive(passphrase)
	enc_key = key_material[:AES_KEY_SIZE]
	mac_key = key_material[AES_KEY_SIZE:]
	return enc_key, mac_key


def encrypt_file(fich: str) -> None:
	#Cifra um ficheiro com AES-CTR e gera HMAC (encrypt-then-MAC).
	passphrase = getpass.getpass("Pass-phrase: ").encode()

	with open(fich, "rb") as f:
		plaintext = f.read()

	salt = os.urandom(SALT_SIZE)
	nonce = os.urandom(NONCE_SIZE)
	enc_key, mac_key = derive_keys(passphrase, salt)

	cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()

	# Encrypt-then-MAC: autentica salt || nonce || ciphertext
	h = hmac.HMAC(mac_key, hashes.SHA256())
	h.update(salt + nonce + ciphertext)
	tag = h.finalize()

	out_file = f"{fich}.enc"
	with open(out_file, "wb") as out:
		# formato: salt (16) | nonce (16) | ciphertext | tag (32)
		out.write(salt + nonce + ciphertext + tag)

	print(f"[OK] Ficheiro cifrado e autenticado: {out_file}")


def decrypt_file(fich: str) -> None:
	#Verifica HMAC do criptograma e, se válido, decifra com AES-CTR.
	passphrase = getpass.getpass("Pass-phrase: ").encode()

	with open(fich, "rb") as f:
		data = f.read()

	min_size = SALT_SIZE + NONCE_SIZE + TAG_SIZE
	if len(data) < min_size:
		raise ValueError("Criptograma inválido: tamanho insuficiente para salt, NONCE e TAG.")

	salt = data[:SALT_SIZE]
	nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
	tag = data[-TAG_SIZE:]
	ciphertext = data[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

	enc_key, mac_key = derive_keys(passphrase, salt)

	# Primeiro verifica integridade/autenticidade, só depois decifra
	h = hmac.HMAC(mac_key, hashes.SHA256())
	h.update(salt + nonce + ciphertext)
	try:
		h.verify(tag)
	except InvalidSignature as exc:
		raise ValueError("Falha de autenticacao: MAC invalido.") from exc

	cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(ciphertext) + decryptor.finalize()

	out_file = f"{fich}.dec"
	with open(out_file, "wb") as out:
		out.write(plaintext)

	print(f"[OK] Ficheiro autenticado e decifrado: {out_file}")


def usage() -> None:
	#Mostra a forma de utilização do programa na linha de comandos.
	print("Uso:")
	print("  enc <fich>   -- cifra com AES-CTR e autentica com HMAC")
	print("  dec <fich>   -- verifica HMAC e decifra")


def main() -> None:
	#Processa argumentos e executa a operação pedida (enc ou dec).
	if len(sys.argv) != 3:
		usage()
		sys.exit(1)

	op = sys.argv[1].lower()

	try:
		if op == "enc":
			encrypt_file(sys.argv[2])
		elif op == "dec":
			decrypt_file(sys.argv[2])
		else:
			usage()
			sys.exit(1)

	except FileNotFoundError as e:
		print(f"[ERRO] Ficheiro nao encontrado: {e.filename}")
		sys.exit(1)
	except ValueError as e:
		print(f"[ERRO] {e}")
		sys.exit(1)
	except Exception as e:
		print(f"[ERRO] {e}")
		sys.exit(1)


if __name__ == "__main__":
	main()


#python pbenc_aes_ctr_hmac.py enc ficheiro.txt
#python pbenc_aes_ctr_hmac.py dec ficheiro.txt.enc