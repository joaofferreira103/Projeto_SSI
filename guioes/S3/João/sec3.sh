#!/bin/bash 

# Exercicio 1 
sudo touch mycat.c # como é que o musk fez sem sudo???

# Exercicio 2
sudo adduser userssi

# Exercicio 3  
sudo chown userssi mycat.c
sudo chown userssi braga.txt

# Exercicio 4
gcc mycat.c -o mycat
./mycat braga.txt
# Permission denied

# Exercicio 5
sudo chmod u+s mycat

# Exercicio 6
./mycat braga.txt
# Funcionou 