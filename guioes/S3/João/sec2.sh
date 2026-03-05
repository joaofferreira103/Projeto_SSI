#!/bin/bash

# Exercicio 0
cat /etc/passwd
cat /etc/group 

# Exercicio 1
sudo adduser danran
sudo adduser musk 
sudo adduser moana

# Exercicio 2
sudo groupadd grupo-ssi
sudo usermod -aG grupo-ssi danran
sudo usermod -aG grupo-ssi musk
sudo usermod -aG grupo-ssi moana
sudo groupadd par-ssi
sudo usermod -aG par-ssi danran
sudo usermod -aG par-ssi musk

# Exercicio 3 
cat /etc/passwd 
cat /etc/group
# Resposta:
# Sim, observaram-se diferenças:
# - Ficheiro /etc/passwd: Foram adicionadas novas linhas no final, correspondentes aos 
#   novos utilizadores criados, indicando o seu nome, UID, GID e diretoria home.
# - No ficheiro /etc/group: Foram adicionadas entradas para os novos grupos (grupo-ssi e par-ssi).
#   Além disso, os nomes dos utilizadores aparecem agora listados no final das linhas 
#   dos respetivos grupos aos quais foram adicionados[cite: 19, 22].

#Exercicio 4
sudo chown danran aula/braga.txt 

# Exercicio 5
cat aula/braga.txt
# permission denied 

# Exercicio 6
su - danran
nano braga.txt
# O utilizador danran tem permissão de leitura e escrita no ficheiro braga.txt

# Exercicio 7
id 
# uid=1001(danran) gid=1001(danran) groups=1001(danran),100(users),1004(grupo-ssi),1005(par-ssi)
groups 
#danran users grupo-ssi par-ssi

# Exercicio 8
nano braga.txt
# tudo igual????? perguntar ao musk

# Exercicio 9
cd dir2 
#Permission denied 
