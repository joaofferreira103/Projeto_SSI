# Exercício 1: Explicação das Flags de Compilação

## Flags de Compilação Utilizadas

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -g
```

---

## Explicação Detalhada de Cada Flag

### **1. `-fno-stack-protector`**

**Função:** Desabilita o **stack canary** (protetor de stack)

**Explicação Técnica:**
- O stack canary é uma mitigação de segurança que insere um valor aleatório e único imediatamente antes do return address na stack.
- Quando a função termina, o compilador verifica se este valor foi alterado. Se foi, o programa detecta um possível buffer overflow e termina antes de executar o return address corrompido.
- Ao desabilitar com `-fno-stack-protector`, removemos esta proteção, deixando a vulnerabilidade totalmente exposta para exploração.

**Por quê usar neste laboratório:**
- Permite demonstrar o buffer overflow de forma clara sem defesas que obscureceriam o aprendizado.
- Sem esta flag, o exploit não funcionaria.

**Nota importante:** Em código de produção, **nunca** se deve usar esta flag. Os compiladores modernos ativam stack protection por defeito.

---

### **2. `-z execstack`**

**Função:** Marca a **stack como executável** (permissões RWX em vez de RW)

**Explicação Técnica:**
- Por defeito, em sistemas modernos, a stack tem permissões Read-Write (RW) mas **não** Executable (NX/DEP - Data Execution Prevention).
- Isto previne o ataque clássico de "stack injection" onde um atacante injeta shellcode (código malicioso) no buffer e depois o executa.
- Ao usar `-z execstack`, tornamos a stack executável, permitindo que um potencial atacante execute código diretamente da stack.

**Por quê usar neste laboratório:**
- Demonstra o impacto da proteção DEP/NX e como a sua ausência permite certos tipos de ataque.
- Ilustra por que é tão importante que o sistema operativo e compilador desabilitem a execução de dados.

**Nota importante:** Em produção, a stack **deve ser non-executable**. Esta é uma proteção fundamental de segurança.

---

### **3. `-no-pie`**

**Função:** Desabilita **Position Independent Executable (PIE)** e usa endereços absolutos fixos

**Explicação Técnica:**
- Por defeito, muitos compiladores modernos ativam PIE, o que significa que o código executável é compilado como "Position Independent Code" (PIC).
- PIE, combinado com ASLR (Address Space Layout Randomization) do sistema operativo, randomiza o layout de memória do programa a cada execução.
- Isto torna o endereço de qualquer função diferente em cada execução, dificultando exploits que dependem de endereços conhecidos.
- Ao usar `-no-pie`, o programa usa endereços absolutos fixos. Isto significa que `secret_function()` sempre está no mesmo endereço, facilitando enormemente a exploração.

**Por quê usar neste laboratório:**
- Deixa o exploit **determinístico** — os endereços são previsíveis e sempre iguais.
- Em conjunto com desabilitar ASLR no sistema, garante que o endereço alvo é conhecido antes de executar o programa.

**Nota importante:** Em sistemas modernos com ASLR ativo, exploits de buffer overflow tornam-se muito mais difíceis. PIE é uma proteção importante.

---

### **4. `-g`**

**Função:** Inclui **símbolos de debug** no executável

**Explicação Técnica:**
- Insere informações de debug (nomes de variáveis, funções, números de linha, tipos) no binário compilado.
- Permite ao GDB (ou outro debugger) mostrar código-fonte, nomes de funções e variáveis em vez de apenas endereços hexadecimais.
- Facilita a análise e o debugging, permitindo-nos ver exatamente onde estão os buffers, a função secreta, e como a stack é disposta.

**Por quê usar neste laboratório:**
- Essencial para debugar interativamente com GDB.
- Permite verificar endereços de variáveis e estrutura da stack facilmente.
- Sem `-g`, o GDB sendo-nos seria praticamente inútil.

**Desvantagem:** Aumenta o tamanho do binário de forma notória, mas não afeta o comportamento em execução.

---

## Resumo

| Flag | Efeito | Por Quê Usar |
|------|--------|--------------|
| `-fno-stack-protector` | Remove canary de stack | Deixa buffer overflow explorável |
| `-z execstack` | Deixa stack executável | Permite code injection na stack |
| `-no-pie` | Endereços absolutos fixos | Torna exploração determinística |
| `-g` | Inclui símbolos de debug | Facilita análise com GDB |

**Conclusão:** Todas estas flags foram escolhidas para **remover mitigações de segurança** e tornar a vulnerabilidade totalmente explorável de forma educacional. **Em código de produção, nenhuma destas flags deve ser usada.** Os sistemas e compiladores modernos ativam estas proteções por defeito exatamente para prevenir este tipo de vulnerabilidades.

