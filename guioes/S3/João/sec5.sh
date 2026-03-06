#!/bin/bash 

# Exercicio 1
capsh --print

# Exercicio 2
touch webserver.c
nano webserver.c
# Código do webserver.c
./webserver 4050
# Success: binded to port 4050

# Exercicio 3
./webserver 80
# Errr on bind: Permission denied
# O processo não tem permissão para usar a porta 80
# pois que é uma porta privilegiada (abaixo de 1024).

sudo setcap 'cap_net_bind_service=+ep' webserver
./webserver 80
# Success: binded to port 80


