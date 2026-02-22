#!/bin/bash
# Exercício 0
ls -l /etc/passwd
ls -l /etc/group
# Exercício 1
sudo adduser musk
sudo adduser danran
sudo adduser moana
# Exercício 2
sudo groupadd grupo-ssi
sudo usermod -aG grupo-ssi musk
sudo usermod -aG grupo-ssi danran
sudo usermod -aG grupo-ssi moana
sudo groupadd par-ssi
sudo usermod -aG par-ssi musk
sudo usermod -aG par-ssi danran
# Exercício 3
ls -l /etc/passwd
ls -l /etc/group
# Exercício 4
sudo chown musk braga.txt 
# Exercício 5
nano braga.txt
# permission denied
# Exercício 6
su - musk
nano braga.txt
# consigo ler o ficheiro e escrever o ficheiro
# Exercício 7
id
#uid=1001(musk) gid=1001(musk) groups=1001(musk),1004(grupo-ssi),1005(par-ssi)
groups
#musk grupo-ssi par-ssi
# Exercicio 8
nano braga.txt
#File 'braga.txt' is unwritable
# Exercício 9
cd dir2
# Permission denied

