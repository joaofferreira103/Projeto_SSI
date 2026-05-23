import sys

from cesar import cifra_cesar, preproc


def encontra_chave_e_texto_limpo(criptograma, palavras):
    criptograma = preproc(criptograma)
    palavras = [preproc(palavra) for palavra in palavras if preproc(palavra)]

    for deslocamento in range(26):
        texto_limpo = cifra_cesar(criptograma, -deslocamento)
        if any(palavra in texto_limpo for palavra in palavras):
            chave = chr(ord("A") + deslocamento)
            return chave, texto_limpo

    return None, None


def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cesar_attack.py <criptograma> <palavra1> [palavra2 ...]")
        return

    criptograma = sys.argv[1]
    palavras = sys.argv[2:]

    chave, texto_limpo = encontra_chave_e_texto_limpo(criptograma, palavras)

    if chave is None:
        return

    print(chave)
    print(texto_limpo)


if __name__ == "__main__":
    main()