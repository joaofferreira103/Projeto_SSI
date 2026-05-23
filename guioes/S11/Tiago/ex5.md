# Exercício 5: Remediação Segura

## Objetivo

O objetivo deste exercício foi modificar o código vulnerável presente no arquivo `vuln.c` para eliminar a vulnerabilidade de buffer overflow. Para isso, foram realizadas as seguintes alterações:

1. Substituição da função insegura `strcpy` por uma alternativa segura (`strncpy`).
2. Adição de uma verificação explícita de comprimento para evitar que entradas maiores que o buffer sejam copiadas.
3. Compilação do código com todas as mitigações de segurança padrão ativas.

---

## Código Corrigido

O código corrigido foi salvo no arquivo `vulnex5.c` e está apresentado abaixo:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void secret_function(void) {
    printf("\n[!] ACCESS GRANTED: you reached the secret function!\n");
    printf("[!] In a real exploit, this could be arbitrary code execution.\n\n");
    exit(0);
}

void process_input(char *input) {
    char buffer[64];
    printf("[*] Buffer is at:         %p\n", (void *)buffer);
    printf("[*] secret_function is at: %p\n", (void *)secret_function);

    // Verificação de comprimento para evitar overflow
    if (strlen(input) >= sizeof(buffer)) {
        fprintf(stderr, "[!] Input too long! Buffer overflow prevented.\n");
        exit(1);
    }

    // Uso de strncpy para limitar a cópia ao tamanho do buffer
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Garantir terminação nula

    printf("[*] You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }
    printf("[*] process_input return address is on the stack.\n");
    process_input(argv[1]);
    printf("[*] Normal programme termination.\n");
    return 0;
}
```

---

## Justificativa das Alterações

### Substituição de `strcpy` por `strncpy`
A função `strcpy` não realiza nenhuma verificação de limites, o que permite que entradas maiores que o buffer sobrescrevam áreas adjacentes da memória, causando vulnerabilidades de segurança. A função `strncpy` foi utilizada para limitar a cópia ao tamanho do buffer, prevenindo o overflow.

### Verificação Explícita de Comprimento
Antes de copiar os dados para o buffer, foi adicionada uma verificação explícita para garantir que o tamanho da entrada não exceda o tamanho do buffer. Caso a entrada seja muito longa, o programa exibe uma mensagem de erro e termina a execução de forma segura.

### Compilação com Mitigações Ativas
O código corrigido deve ser compilado com todas as mitigações de segurança padrão ativas, como Stack Canary, ASLR e DEP. O comando de compilação recomendado é:

```bash
gcc -o vulnex5 vulnex5.c -g
```

Essas mitigações adicionam camadas extras de proteção contra exploits, tornando o programa mais seguro.

---

## Conclusão

Com as alterações realizadas, o código corrigido elimina a vulnerabilidade de buffer overflow, garantindo que entradas excessivamente longas sejam tratadas de forma segura. Além disso, a compilação com mitigações de segurança padrão reforça ainda mais a proteção contra ataques. O programa agora está alinhado com as melhores práticas de segurança em desenvolvimento de software.