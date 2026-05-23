import sys

def preproc(str):
    l = []
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)


def chave_para_deslocamento(chave):
    chave = preproc(chave)
    if len(chave) != 1:
        raise ValueError("A chave tem de ser uma única letra de A a Z.")
    return ord(chave) - ord("A")


def cifra_cesar(mensagem, deslocamento):
    resultado = []
    for c in preproc(mensagem):
        posicao = ord(c) - ord("A")
        nova_posicao = (posicao + deslocamento) % 26
        resultado.append(chr(ord("A") + nova_posicao))
    return "".join(resultado)


def main():
    

    if len(sys.argv) != 4:
        print("Uso: python3 cesar.py <enc|dec> <A-Z> <mensagem>")
        return

    operacao = sys.argv[1].lower()
    chave = sys.argv[2]
    mensagem = sys.argv[3]

    deslocamento = chave_para_deslocamento(chave)

    if operacao == "enc":
        print(cifra_cesar(mensagem, deslocamento))
    elif operacao == "dec":
        print(cifra_cesar(mensagem, -deslocamento))
    else:
        print("A operação tem de ser 'enc' ou 'dec'.")


if __name__ == "__main__":
    main()


