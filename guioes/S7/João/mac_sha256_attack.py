# Length extension attack sobre prefix-MAC: MAC(k, m) = SHA256(k || m)
# Sem conhecer a chave, forja um MAC válido para m || padding || ext
import sys
import hashpumpy

KEY_SIZE = 32  # deve coincidir com mac_sha256.py
MAC_SIZE = 32  # SHA256 produz 32 bytes


def usage() -> None:
    print("Uso: python mac_sha256_attack.py <fich> <ext>")
    print("  <fich>      -- ficheiro com a mensagem original")
    print("  <fich>.mac  -- ficheiro com o MAC original (deve existir)")
    print("  <ext>       -- texto a acrescentar à mensagem")


def main() -> None:
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)

    fich = sys.argv[1]
    ext = sys.argv[2].encode("utf-8")

    # ler mensagem original
    with open(fich, "rb") as f:
        original_msg = f.read()

    # ler MAC original (32 bytes) e converter para hex
    mac_file = f"{fich}.mac"
    with open(mac_file, "rb") as f:
        original_mac_bytes = f.read()

    if len(original_mac_bytes) != MAC_SIZE:
        raise ValueError(f"MAC inválido: esperado {MAC_SIZE} bytes, obtido {len(original_mac_bytes)} bytes.")

    original_mac_hex = original_mac_bytes.hex()

    # length extension attack:
    #   hashpumpy recebe o MAC conhecido, a mensagem, a extensão e o tamanho da chave
    #   devolve (novo_mac_hex, nova_mensagem_bytes)
    #   nova_mensagem = original_msg || padding || ext
    # Em Python 3, hashpumpy costuma trabalhar com str. Usamos latin-1 para
    # preservar a correspondência 1:1 entre bytes e caracteres.
    original_msg_str = original_msg.decode("latin-1")
    ext_str = ext.decode("latin-1")

    new_mac_hex, new_msg = hashpumpy.hashpump(
        original_mac_hex,
        original_msg_str,
        ext_str,
        KEY_SIZE
    )

    if isinstance(new_msg, str):
        new_msg = new_msg.encode("latin-1")

    # gravar mensagem estendida
    ext_msg_file = f"{fich}.ext"
    with open(ext_msg_file, "wb") as f:
        f.write(new_msg)

    # gravar MAC forjado
    ext_mac_file = f"{fich}.ext.mac"
    with open(ext_mac_file, "wb") as f:
        f.write(bytes.fromhex(new_mac_hex))

    print(f"[OK] Mensagem estendida gravada em : {ext_msg_file}")
    print(f"[OK] MAC forjado gravado em        : {ext_mac_file}")

    # mostrar o padding acrescentado (diferença entre nova e original mensagem menos a extensão)
    padding = new_msg[len(original_msg):len(new_msg) - len(ext)]
    print(f"\n[INFO] Padding acrescentado ({len(padding)} bytes):")
    print("  " + " ".join(f"{b:02x}" for b in padding))
    print(f"\n[VERIFICAÇÃO] Corra agora:")
    print(f"  python mac_sha256.py ver {ext_msg_file} <fkey>")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"[ERRO] Ficheiro não encontrado: {e.filename}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERRO] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)




#python3 -m pip install hashpumpy
#python3 mac_sha256.py setup test.key
#python3 mac_sha256.py mac ficheiro.txt test.key
#python3 mac_sha256_attack.py ficheiro.txt "&admin=true"
#python3 mac_sha256.py ver ficheiro.txt.ext test.key