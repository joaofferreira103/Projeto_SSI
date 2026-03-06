#!/bin/bash 

# Exercicio 1
getfacl porto.txt

# Exercicio 2
sudo setfacl -m g:grupo-ssi:w porto.txt

# Exercicio 3
getfacl porto.txt
# Resposta:
# Agora o grupo-ssi tem permissão de escrita no ficheiro porto.txt 

# Exercicio 4
su - danran
# Erro ao tentar ler porto.txt: Permission denied

