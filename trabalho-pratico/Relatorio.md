# Relatório do Trabalho Prático

**Segurança de Sistemas Informáticos, 2025/2026**

**Licenciatura em Engenharia Informática, Universidade do Minho**

---
## 0. Introdução

Este relatório apresenta informações relativas ao Trabalho Prático da Unidade Curricular Sistemas de Segurança Informática, pertencente ao 3º Ano da Licenciatura em Engenharia Informática da Universidade do Minho, realizada no ano letivo 2025/2026.

Este projeto foi realizado pelos seguintes estudantes:
- João Pedro Ferreira e Ferreira, a104539;
- Maria Inês da Rocha Pinto Gracias Fernandes, a104522;
- Tiago Rodrigues Barros, a104530.

O projeto consiste no desenvolvimento de um sistema de conversação seguro com End-to-End Encryption (E2EE), implementado em Python com recurso à biblioteca cryptography. O objetivo central é garantir que o conteúdo das mensagens permaneça inacessível a terceiros — incluindo o próprio servidor que coordena as comunicações — assegurando confidencialidade, integridade e autenticidade em todas as trocas de informação.

O relatório está organizado em três secções principais: arquitetura e fluxos de comunicação (incluindo gestão de chaves), modelo de segurança (primitivas, garantias e limitações), e uma breve discussão de melhorias que não foram implementadas.


---

## 1. Arquitetura da Solução

### 1.1 Visão Geral

O sistema segue um modelo cliente-servidor sobre TCP. O servidor atua como ponto central de coordenação e encaminhamento, mas **nunca tem acesso ao conteúdo das mensagens** — toda a cifragem e decifragem ocorre exclusivamente nos clientes. O servidor é tratado como *honest-but-curious*: confia-se na sua integridade funcional, mas não na sua confidencialidade.

O projeto está organizado em três módulos principais:

| Módulo | Ficheiro | Responsabilidade |
|--------|----------|-----------------|
| Protocolo de rede | `common/protocol.py` | Framing TCP, serialização JSON |
| Criptografia | `common/crypto.py` | Todas as primitivas criptográficas |
| Servidor | `server/server.py` + `server/database.py` | Routing, persistência, gestão de utilizadores |
| Cliente | `client/client.py` | Interface, gestão de chaves, cifra/decifra |

### 1.2 Protocolo de Comunicação

O TCP é um protocolo de streams sem conceito de fronteiras de mensagem. Para resolver este problema, foi implementado **length-prefix framing** em `protocol.py`:

```
[ 4 bytes: tamanho do payload (big-endian uint32) ] [ payload em bytes ]
```

Todas as mensagens trocadas são serializadas em JSON, o que permite extensibilidade sem quebrar compatibilidade — adicionar um novo campo a um tipo de mensagem não afecta a leitura de campos existentes. A camada de transporte (`send_message`/`recv_message`) lida com bytes; a camada de protocolo (`send_json`/`recv_json`) lida com dicionários Python.

### 1.3 Autenticação e Ciclo de Vida da Ligação

Cada ligação TCP tem uma máquina de estados explícita com duas fases:

**Fase A — UNAUTHENTICATED:** O cliente só pode enviar mensagens do tipo `register` ou `login`. Qualquer outro tipo é rejeitado com erro. Esta separação é aplicada no servidor antes de qualquer operação privilegiada.

**Fase B — AUTHENTICATED:** Após login bem-sucedido, o utilizador entra no loop de mensagens. O servidor regista o socket no dicionário `connected_users` (protegido por `threading.Lock`) e a chave pública efémera é publicada na base de dados.

```
CLIENT conecta
    │
    V
UNAUTHENTICATED
    ├─ register -> DB.register_user() -> ok / error
    └─ login    -> DB.verify_user()   -> ok / error
                                            │
                                      AUTHENTICATED
                                            ├─ publish_key
                                            ├─ get_key / get_offline_key
                                            ├─ message (routing / store)
                                            ├─ sync_offline_messages
                                            ├─ key_rotate
                                            └─ quit -> close
```

O servidor é multi-threaded: para cada `accept()` é criada uma *daemon thread* dedicada. O `SO_REUSEADDR` está ativo para evitar o período de espera *TIME_WAIT* durante o desenvolvimento.

### 1.4 Gestão de Chaves

O sistema utiliza **dois tipos de chaves X25519** por utilizador, com ciclos de vida distintos:

#### Chaves de Sessão (Efémeras)

Geradas a cada login com `generate_x25519_keypair()`. São publicadas no servidor logo após autenticação e eliminadas na base de dados quando o utilizador faz logout. Nunca saem do cliente em texto claro — apenas a chave pública (32 bytes em hex) é enviada ao servidor.

O fluxo de troca de chaves de sessão (`/connect`) é o seguinte:

```
Alice faz login  ->  publica pub_A no servidor
Bob faz login    ->  publica pub_B no servidor

Alice: /connect bob
  └─ servidor devolve pub_B
  └─ Alice calcula ECDH(priv_A, pub_B) -> HKDF -> session_key_AB

Bob recebe key_response com pub_A (enviado proativamente pelo servidor)
  └─ Bob calcula ECDH(priv_B, pub_A) -> HKDF -> session_key_AB

session_key_AB é idêntico em ambos os lados — o servidor nunca o vê.
```

#### Chaves Offline (Persistentes)

Geradas uma única vez por utilizador com `generate_offline_keypair()`. Permitem receber mensagens cifradas mesmo quando o destinatário está offline. A chave privada offline é cifrada com AES-256-GCM (derivando a chave de cifra via PBKDF2-SHA256 a partir da password e do username) e guardada localmente em `~/.chat_offline_keys/<username>.key` com permissões `0o600`. A chave pública correspondente é publicada no servidor de forma persistente (não é apagada no logout).

#### Rotação de Chaves (Forward Secrecy)

Após cada `KEY_ROTATION_THRESHOLD` mensagens trocadas com um peer, o cliente inicia uma rotação:

1. Gera um novo par X25519 efémero
2. Publica a nova chave pública no servidor
3. Notifica o peer via mensagem `key_rotate`
4. Ambos os lados fazem novo handshake e derivam um novo `session_key`
5. A chave privada anterior é descartada (substituída em memória)

Isto garante que, mesmo que uma chave de sessão seja comprometida no futuro, as mensagens anteriores permanecem protegidas.

### 1.5 Mensagens Offline (Valorização)

Quando o destinatário não está ligado, o servidor armazena a mensagem cifrada na tabela `offline_messages` (SQLite). A mensagem é cifrada pelo remetente com a **chave offline do destinatário** (obtida via `get_offline_key`), pelo que o servidor armazena apenas ciphertext — nunca plaintext.

Após login, o cliente carrega a sua chave offline, envia `sync_offline_messages`, e o servidor entrega as mensagens acumuladas. O cliente usa a sua chave privada offline e a chave pública offline do remetente (incluída no envelope) para derivar o segredo partilhado e decifrar. As mensagens são apagadas da base de dados após entrega.

---

## 2. Modelo de Segurança

### 2.1 Primitivas Criptográficas

Toda a lógica criptográfica está centralizada em `common/crypto.py`. Nenhum outro ficheiro importa directamente da biblioteca `cryptography`. Esta decisão facilita auditoria de segurança: existe um único ponto de controlo para todas as operações sensíveis.

#### X25519 — Troca de Chaves ECDH

O X25519 (Curve25519) foi escolhido por ser resistente a ataques de timing side-channel por design, ter implementação simples e segura, e ser amplamente auditado. O output directo do ECDH é um ponto de curva com estrutura matemática que reduz a entropia efectiva, pelo que não é usado directamente como chave AES.

#### HKDF-SHA256 — Derivação de Chave de Sessão

O resultado bruto do ECDH é processado por HKDF (*Hash-based Key Derivation Function*) com SHA-256, produzindo 32 bytes uniformemente distribuídos adequados para AES-256. São usados dois `info` strings distintos para separar semanticamente os dois tipos de chave:

- `b"chat-e2ee-v1"` — chaves de sessão efémeras
- `b"chat-e2ee-offline-v1"` — chaves para mensagens offline

#### AES-256-GCM — Cifra Simétrica Autenticada

AES-256-GCM garante simultaneamente **confidencialidade** (ninguém sem a chave lê o plaintext) e **integridade/autenticidade** (qualquer modificação do ciphertext é detectada via *GCM tag*). O nonce de 12 bytes é gerado aleatoriamente por `os.urandom()` para cada mensagem — a reutilização de nonce com GCM comprometeria a segurança, pelo que a aleatoriedade é crítica. O formato no fio é `nonce (12 bytes) || ciphertext || GCM tag (16 bytes)`, serializado como hex.

Se a tag GCM falhar na verificação (chave errada ou mensagem adulterada), é lançada `InvalidTag` — o cliente captura esta exceção e descarta a mensagem sem a apresentar ao utilizador.

#### Scrypt — Hashing de Passwords

As passwords são armazenadas com Scrypt (parâmetros: `N=2^14, r=8, p=1`, sal aleatório de 16 bytes por utilizador). O Scrypt é *memory-hard*, o que dificulta ataques de força bruta com GPUs ou ASICs. O sal aleatório por utilizador impede ataques de *rainbow table*. O formato armazenado é `salt_hex:hash_hex`.

A verificação de login usa timing constante (via `kdf.verify()` da biblioteca `cryptography`) para evitar ataques de timing que permitiriam inferir se uma password está "quase certa".

Como mitigação adicional contra enumeração de utilizadores, quando o utilizador não existe, é executado o trabalho completo do Scrypt antes de retornar erro — assim o tempo de resposta é idêntico para utilizadores existentes e inexistentes.

#### PBKDF2-SHA256 — Protecção da Chave Offline Local

A chave privada offline é cifrada localmente com uma chave derivada de `PBKDF2(password, SHA256(username)[:16], iterations=100000)`. O uso do username como sal determinístico garante que a mesma combinação password+username produz sempre a mesma chave-mestra — necessário para recuperação da chave offline em caso de perda do ficheiro (desde que o utilizador lembre a password).

### 2.2 Garantias de Segurança

| Propriedade | Mecanismo | Cobertura |
|-------------|-----------|-----------|
| Confidencialidade das mensagens | AES-256-GCM com chave derivada via ECDH+HKDF | Mensagens online e offline |
| Integridade e autenticidade | GCM tag (AEAD) | Todas as mensagens cifradas |
| Confidencialidade das passwords | Scrypt com sal aleatório | Base de dados do servidor |
| Forward secrecy | Rotação periódica de chaves efémeras | Sessões ativas |
| Confidencialidade da chave offline local | AES-256-GCM + PBKDF2 | Ficheiro local `~/.chat_offline_keys/` |
| Protecção contra timing attacks | Scrypt constante + timing-safe verify | Autenticação |
| Servidor honest-but-curious | E2EE: servidor só vê ciphertext | Conteúdo de mensagens |

### 2.3 Limitações e Vulnerabilidades Identificadas

**Ausência de PKI / autenticação de identidade:** O sistema não tem mecanismo de verificação da identidade dos pares. O servidor pode, em princípio, registar um utilizador falso com o mesmo nome e substituir chaves públicas (*key substitution attack*). Um utilizador malicioso ou um servidor comprometido poderia realizar um ataque man-in-the-middle ativo durante a troca de chaves. A mitigação completa requeria um sistema PKI com certificados assinados por uma CA ou verificação *out-of-band* das chaves públicas (ex: fingerprint comparado por outro canal).

**Chave offline com sal determinístico:** O sal do PBKDF2 para a chave offline é derivado deterministicamente de `SHA256(username)[:16]`. Isto significa que dois utilizadores com a mesma password têm a mesma chave-mestra offline se tiverem o mesmo username — o que é impossível (usernames são únicos), mas é uma limitação conceptual. Seria mais seguro usar um sal verdadeiramente aleatório, aceitar a perda de recuperabilidade determinística, ou armazenar o sal cifrado de outra forma.

**Sem verificação de integridade das mensagens offline no servidor:** O servidor armazena ciphertext sem verificar a sua validade. Um utilizador malicioso poderia inundar a tabela `offline_messages` com mensagens falsas. Mitigação: limitar o número de mensagens offline por destinatário ou exigir autenticação adicional do remetente no ato de armazenamento.

**Sem autenticação do canal cliente-servidor:** As mensagens trocadas entre cliente e servidor (JSON sobre TCP) não são protegidas por TLS. Um atacante com acesso à rede pode observar metadados (quem comunica com quem, quando, tamanho das mensagens) mesmo que não consiga ler o conteúdo. A confidencialidade do conteúdo é garantida pelo E2EE, mas os metadados ficam expostos.

**Rotação de chaves não-sincronizada:** A rotação é iniciada de forma unilateral com base no contador de mensagens enviadas localmente. Existe uma janela de tempo em que um lado já rotacionou e o outro ainda não — mensagens enviadas neste intervalo podem falhar a decifrar. O código trata isso com fallback para a chave offline, mas é uma fonte de complexidade e possíveis erros.

---

## 3. Melhorias Não Implementadas

### 3.1 PKI / Autoridade de Certificação

A valorização mais impactante em termos de segurança seria implementar um servidor que atuasse como CA *self-signed*. Cada utilizador geraria um par de chaves de longo prazo (ex: Ed25519), obteria um certificado assinado pelo servidor no registo, e todas as chaves de sessão publicadas seriam assinadas com essa chave de longo prazo. Os clientes verificariam a assinatura antes de aceitar qualquer chave pública, eliminando os ataques de substituição de chave descritos na secção 2.3.

Esta funcionalidade requeria alterações substanciais: novo tipo de chave (Ed25519 para assinaturas), novo fluxo no registo, nova tabela na base de dados, e validação em todos os `get_key` / `get_offline_key`.

### 3.2 Mensagens de Grupo

A implementação de chats multi-utilizador com E2EE requeria um esquema de distribuição de chaves de grupo (ex: cada membro cifra a chave de grupo com a chave pública de cada outro membro). A gestão de acessos (adição/remoção de membros) e a rotação da chave de grupo com *forward secrecy* introduzem complexidade significativa que ficou fora do âmbito do projecto.

### 3.3 Sincronização de Rotação por Tempo

A rotação de chaves foi implementada com base em contagem de mensagens. Uma abordagem mais robusta combinaria contagem de mensagens com um timeout temporal (o que surgir primeiro), garantindo rotação mesmo em conversas com poucas mensagens mas de longa duração. Optou-se por não implementar esta variante porque requeria sincronização de relógios entre cliente e servidor.

---

## 4. Conclusões

O sistema desenvolvido concretiza os objectivos definidos no enunciado: um chat com E2EE real, onde o servidor nunca tem acesso ao conteúdo das mensagens, e onde as comunicações estão protegidas contra adversários passivos e, em parte, activos. As primitivas criptográficas escolhidas — X25519, HKDF-SHA256, AES-256-GCM e Scrypt — são modernas, bem auditadas e adequadas aos requisitos de segurança. A centralização de toda a lógica criptográfica em `common/crypto.py` facilita auditoria e manutenção.

Das valorizações propostas, foram implementadas mensagens offline com E2EE preservado (o servidor armazena apenas ciphertext) e *forward secrecy* por rotação periódica de chaves efémeras. A principal limitação identificada é a ausência de autenticação de identidade criptográfica: sem PKI, o sistema está protegido contra um servidor passivo, mas não contra um servidor activo que substitua chaves públicas.

Em suma, o projeto atingiu os principais objetivos propostos e permitiu aplicar de forma integrada conceitos fundamentais de segurança de sistemas informáticos.