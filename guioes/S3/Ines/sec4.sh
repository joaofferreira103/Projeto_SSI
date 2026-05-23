# Exercicio 1
getfacl porto.txt

# Exercicio 2
setfacl -m g:grupo-ssi:w porto.txt

# Exercicio 3
getfacl porto.txt
# Apareceu agora o grupo-ssi com permissão de escrita e um mask com permissao de leitura e escrita

# Exercicio 4
su musk
nano porto.txt
# consigo escrever no ficheiro
nano porto.txt
# Error reading porto.txt: Permission denied
