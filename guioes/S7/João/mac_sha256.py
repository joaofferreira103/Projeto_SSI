# Calcula o MAC de um ficheiro usando prefix-MAC: MAC(k, m) = SHA256(k || m)
import os #gera a chave de forma aleatória
import sys #para ler os argumentos da linha de comando
import secrets #para comparação segura de MACs
from cryptography.hazmat.primitives import hashes #para usar a função de hash SHA256

KEY_SIZE = 32  # 256 bits

#criação de uma chave aleatória e gravação num ficheiro
def setup_key(fkey: str) -> None:
    key = os.urandom(KEY_SIZE)
    with open(fkey, "wb") as fk:
        fk.write(key)
    print(f"[OK] Chave criada em: {fkey}")

#leitura da chave do ficheiro e verificação do tamanho (deve ser de 32 bytes)
def read_key(fkey: str) -> bytes:
    with open(fkey, "rb") as fk:
        key = fk.read()
    if len(key) != KEY_SIZE:
        raise ValueError(f"Chave inválida: esperado {KEY_SIZE} bytes, obtido {len(key)} bytes.")
    return key

#calcula o MAC usando prefix-MAC: MAC(k, m) = SHA256(k || m)
def prefix_mac(key: bytes, data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key) #adiciona a chave ao início do hash
    digest.update(data) #adiciona a mensagem ao hash
    return digest.finalize()

#calcula o MAC de um ficheiro e grava-o num ficheiro separado com extensão .mac
def compute_mac(fich: str, fkey: str) -> None:
    key = read_key(fkey)

    with open(fich, "rb") as f:
        data = f.read()

    mac = prefix_mac(key, data)

    out_file = f"{fich}.mac"
    with open(out_file, "wb") as out:
        out.write(mac)

    print(f"[OK] MAC gravado em: {out_file}")

#verifica se o MAC armazenado num ficheiro .mac corresponde ao MAC calculado a partir do ficheiro original e da chave
def verify_mac(fich: str, fkey: str) -> None:
    key = read_key(fkey)

    with open(fich, "rb") as f:
        data = f.read()

    mac_file = f"{fich}.mac"
    with open(mac_file, "rb") as f:
        stored_mac = f.read()

    computed_mac = prefix_mac(key, data)
    result = secrets.compare_digest(computed_mac, stored_mac) #comparação segura para evitar ataques de timing
    print(f"[OK] Verificação do MAC: {'PASS' if result else 'FAIL'}")

#mostra como usar o programa, indicando as operações disponíveis e os argumentos necessários para cada uma delas
def usage() -> None:
    print("Uso:")
    print("  setup <fkey>")
    print("  mac   <fich> <fkey>")
    print("  ver   <fich> <fkey>")


def main() -> None:
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    op = sys.argv[1].lower()

    try:
        if op == "setup":
            if len(sys.argv) != 3:
                usage()
                sys.exit(1)
            setup_key(sys.argv[2])

        elif op == "mac":
            if len(sys.argv) != 4:
                usage()
                sys.exit(1)
            compute_mac(sys.argv[2], sys.argv[3])

        elif op == "ver":
            if len(sys.argv) != 4:
                usage()
                sys.exit(1)
            verify_mac(sys.argv[2], sys.argv[3])

        else:
            usage()
            sys.exit(1)

    except FileNotFoundError as e:
        print(f"[ERRO] Ficheiro não encontrado: {e.filename}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


#python mac_sha256.py setup mar.key
#python mac_sha256.py mac ficheiro.txt mar.key
#python mac_sha256.py ver ficheiro.txt mar.key