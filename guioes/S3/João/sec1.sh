#!/bin/bash

# Exercicio 1 
cd ..
cd / 
sudo touch lisboa.txt
sudo touch porto.txt
sudo touch braga.txt

# Exercicio 2
ls -l lisboa.txt

# Exercicio 3
sudo chmod u=rw,g=wr,o=wr lisboa.txt

# Exercicio 4
sudo chmod u=rx porto.txt

# Exercicio 5
chmod o-r braga.txt
chmod g-r braga.txt
chmod u+r braga.txt

# Exercicio 6
sudo mkdir dir1
sudo mkdir dir2
ls -l 

# Exercicio 7
sudo chmod g-x dir2
sudo chmod o-x dir2


