import sys

from cesar import preproc


def chave_para_deslocamentos(chave):
	chave = preproc(chave)
	if not chave:
		raise ValueError("A chave tem de ter pelo menos uma letra.")
	return [ord(c) - ord("A") for c in chave]

# ex: passa de 'BACO' para [1, 0, 2, 14]

def cifra_vigenere(mensagem, chave, cifrar=True):
	mensagem = preproc(mensagem)
	deslocamentos = chave_para_deslocamentos(chave)
	resultado = []

	for i, c in enumerate(mensagem):
		posicao = ord(c) - ord("A")
		deslocamento = deslocamentos[i % len(deslocamentos)]

		if cifrar:
			nova_posicao = (posicao + deslocamento) % 26
		else:
			nova_posicao = (posicao - deslocamento) % 26

		resultado.append(chr(ord("A") + nova_posicao))

	return "".join(resultado)

# com a lista de posições da chave, percorre a mensagem e aplica o deslocamento correspondente
# decide se cifra ou decifra com base no parâmetro cifrar

def main():
	if len(sys.argv) != 4:
		print("Uso: python3 vigenere.py <enc|dec> <chave> <mensagem>")
		return

	operacao = sys.argv[1].lower()
	chave = sys.argv[2]
	mensagem = sys.argv[3]

	if operacao == "enc":
		print(cifra_vigenere(mensagem, chave, True))
	elif operacao == "dec":
		print(cifra_vigenere(mensagem, chave, False))
	else:
		print("A operação tem de ser 'enc' ou 'dec'.")


if __name__ == "__main__":
	main()
