# Exercico 1
capsh --print

# Exercicio 2
touch webserver.c
nano webserver.c
gcc -o webserver webserver.c

# Exercicio 3
./webserver 4050
#Success : binded to port 4050

# Exercicio 4
./webserver 80
# Errr on bind: Permission denied

# Exercicio 5
sudo setcap 'cap_net_bind_service=+ep' ./webserver
./webserver 80
# Success : binded to port 80