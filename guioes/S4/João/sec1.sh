# Exercicio 1
./backupssi
# Directory FD is 3
# Exercicio 2
#a ligação aberta em /root não é fechada automaticamente pelo sistema então quando
# mudamos para um utilizador comum a ligação ainda está aberta e o utilizador comum tem acesso a ela
# Exercicio 3
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/fs.h>

# int main(int argc, char *argv[]) {
#     int dfd = atoi(argv[1]);
#     char buf[4096];
#     long nread;

#     nread = syscall(SYS_getdents64, dfd, buf, sizeof(buf));
    
#     if (nread == -1) {
#         perror("getdents64");
#         return 1;
#     }

    
#     struct linux_dirent64 {
#         unsigned long long d_ino;
#         long long d_off;
#         unsigned short d_reclen;
#         unsigned char d_type;
#         char d_name[];
#     };

#     for (long pos = 0; pos < nread; ) {
#         struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
#         printf("    %s\n", d->d_name);
#         pos += d->d_reclen;
#     }

#     return 0;
# }
./backupssi
#acesso a:
    # .
    # .bashrc
    # .ssh
    # .profile
    # backupssi
    # ..
    # .local

# Exercicio 4
# para corrigir o programa precisamos de fechar o FD antes de largar os privilegios

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

# int main() {
#     int dfd;
#     char *argv[2];

#     dfd = open("/root", O_RDONLY);
#     if (dfd == -1) {
#         perror("open /root");
#         exit(1);
#     }

#     printf("Directory FD is %d\n", dfd);

#     if (mkdir("/root/backupssi", 0700) == -1) {
#         perror("mkdir /root/backupssi");
#     }

#     // CORREÇÃO: fechar o FD ANTES de largar privilégios
#     close(dfd);

#     if (setuid(getuid()) == -1) {
#         perror("setuid");
#         exit(1);
#     }

#     argv[0] = "/bin/sh";
#     argv[1] = NULL;
#     execve(argv[0], argv, NULL);
#     perror("execve");
#     return 0;
# }
