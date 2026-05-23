import sys

NONCE_SIZE = 16


def usage() -> None:
    print("Uso:")
    print("  python chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")


def main() -> None:
    if len(sys.argv) != 5:
        usage()
        sys.exit(1)

    fctxt = sys.argv[1]

    try:
        pos = int(sys.argv[2])
    except ValueError:
        print("[ERRO] <pos> deve ser um inteiro.")
        sys.exit(1)

    old_ptxt = sys.argv[3].encode("utf-8")
    new_ptxt = sys.argv[4].encode("utf-8")

    if len(old_ptxt) != len(new_ptxt):
        print("[ERRO] <ptxtAtPos> e <newPtxtAtPos> devem ter o mesmo tamanho.")
        sys.exit(1)

    if pos < 0:
        print("[ERRO] <pos> deve ser >= 0.")
        sys.exit(1)

    try:
        with open(fctxt, "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print(f"[ERRO] Ficheiro não encontrado: {fctxt}")
        sys.exit(1)

    if len(data) < NONCE_SIZE:
        print("[ERRO] Criptograma inválido.")
        sys.exit(1)

    start = NONCE_SIZE + pos
    end = start + len(old_ptxt)

    if end > len(data):
        print("[ERRO] Intervalo fora dos limites do criptograma.")
        sys.exit(1)

    for i in range(len(old_ptxt)):
        data[start + i] ^= old_ptxt[i] ^ new_ptxt[i]

    out_file = f"{fctxt}.attck"
    with open(out_file, "wb") as f:
        f.write(data)

    print(f"[OK] Criptograma manipulado gravado em: {out_file}")


if __name__ == "__main__":
    main()