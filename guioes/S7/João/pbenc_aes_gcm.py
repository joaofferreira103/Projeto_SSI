import os
import sys
import getpass
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KEY_SIZE = 32          # 256-bit key for AES-GCM
SALT_SIZE = 16         # 128-bit salt for PBKDF2
NONCE_SIZE = 12        # recommended nonce size for GCM
TAG_SIZE = 16          # default AES-GCM tag size in bytes
PBKDF2_ITERATIONS = 480_000


def derive_key(passphrase: bytes, salt: bytes) -> bytes:
	"""Deriva a chave AES-GCM a partir da pass-phrase e do salt via PBKDF2."""
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=KEY_SIZE,
		salt=salt,
		iterations=PBKDF2_ITERATIONS,
	)
	return kdf.derive(passphrase)


def encrypt_file(fich: str) -> None:
	"""Cifra e autentica um ficheiro com AES-GCM usando uma chave derivada da pass-phrase."""
	passphrase = getpass.getpass("Pass-phrase: ").encode()

	with open(fich, "rb") as f:
		plaintext = f.read()

	salt = os.urandom(SALT_SIZE)
	nonce = os.urandom(NONCE_SIZE)
	key = derive_key(passphrase, salt)

	cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()
	tag = encryptor.tag

	out_file = f"{fich}.enc"
	with open(out_file, "wb") as out:
		# formato: salt (16) | nonce (12) | ciphertext | tag (16)
		out.write(salt + nonce + ciphertext + tag)

	print(f"[OK] Ficheiro cifrado e autenticado: {out_file}")


def decrypt_file(fich: str) -> None:
	"""Verifica a tag GCM e, se válida, decifra o ficheiro."""
	passphrase = getpass.getpass("Pass-phrase: ").encode()

	with open(fich, "rb") as f:
		data = f.read()

	min_size = SALT_SIZE + NONCE_SIZE + TAG_SIZE
	if len(data) < min_size:
		raise ValueError("Criptograma invalido: tamanho insuficiente para salt, nonce e tag.")

	salt = data[:SALT_SIZE]
	nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
	tag = data[-TAG_SIZE:]
	ciphertext = data[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

	key = derive_key(passphrase, salt)

	cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
	decryptor = cipher.decryptor()

	try:
		plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	except InvalidTag as exc:
		raise ValueError("Falha de autenticacao: tag GCM invalida.") from exc

	out_file = f"{fich}.dec"
	with open(out_file, "wb") as out:
		out.write(plaintext)

	print(f"[OK] Ficheiro autenticado e decifrado: {out_file}")


def usage() -> None:
	"""Mostra a forma de utilizacao do programa na linha de comandos."""
	print("Uso:")
	print("  enc <fich>   -- cifra e autentica com AES-GCM")
	print("  dec <fich>   -- verifica a tag e decifra")


def main() -> None:
	"""Processa argumentos e executa a operacao pedida (enc ou dec)."""
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


#python pbenc_aes_gcm.py enc ficheiro.txt
#python pbenc_aes_gcm.py dec ficheiro.txt.enc