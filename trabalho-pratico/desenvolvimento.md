## Geral:

SISTEMA DE AUTENTICAÇÃO:

CLIENT connects
    │
    ▼
Server: estado = UNAUTHENTICATED
    │
    ├─ recv {"type": "register", ...} ──► criar user na DB ──► {"type": "ok"} ou {"type": "error"}
    │
    ├─ recv {"type": "login", ...}    ──► verificar hash   ──► {"type": "ok"} ou {"type": "error"}
    │                                                              │
    │                                                    estado = AUTHENTICATED
    │                                                    username guardado na thread
    ▼
  Loop de mensagens (só aceita se AUTHENTICATED)


## Fluxo Geral da troca de chaves:

Alice faz login  →  publica pub_A no servidor
Bob faz login    →  publica pub_B no servidor

Alice escreve:   /connect bob
  → servidor devolve pub_B
  → Alice calcula ECDH(priv_A, pub_B) → HKDF → session_key_AB

Bob escreve:     /connect alice
  → servidor devolve pub_A
  → Bob calcula ECDH(priv_B, pub_A) → HKDF → session_key_AB

session_key_AB é igual nos dois lados — sem o servidor ter acesso



![Texto alternativo](../fotos/Captura%20de%20ecrã%202026-04-10,%20às%2014.51.27.png)



## Onde e como guardar os ultizadores

Guardar chaves dos utilizadores encriptadas numa Base de Dados

Base de dados a utilizar: SQLite, porquê?

não é demasiado complexa e suporta threading, muito fácil de utilizar com python
a outra opção era json mas não suporta threading sem locks e é dificil de escalar.


SECURITY NOTE (honest-but-curious server):
  Even the server only sees the scrypt hash, never the plaintext password.
  An attacker who steals the database still can't recover passwords easily.

## Server

temos ligações tcp threaded (1 thread por socket) assim podemos ter varios clients ligados ao mm tempo

Para cada accept(), cria uma nova thread com handle_client. O SO_REUSEADDR é um detalhe prático, sem ele, cada vez que reiniciavas o servidor durante desenvolvimento terias de esperar ~60 segundos pelo OS.

na fase de routing (quando o servidor tem de entregar mensagens a clientes específicos), vamos precisar de um dicionário partilhado {username: socket} protegido por um threading.Lock()

**PARTE DA AUTENTICAÇÃO**

Cada thread de cliente tem agora dois estados explícitos: UNAUTHENTICATED e AUTHENTICATED. Qualquer mensagem que não seja register/login antes de autenticar é rejeitada. O connected_users dict com um lock vai ser a base do routing na Fase 3.

- Each client thread now has an explicit authentication state machine
  - Messages are now JSON (via send_json/recv_json) instead of raw strings
  - A Database instance is shared across all threads (thread-safe via its own lock)
  - Unauthenticated clients can only send "register" or "login" messages
  - After login, the client enters the (still echoing) chat loop

STATE MACHINE PER CLIENT:
  UNAUTHENTICATED
      |  {"type": "register", "username": ..., "password": ...}
      |       -> DB.register_user() -> {"type": "ok"} or {"type": "error"}
      |
      |  {"type": "login", "username": ..., "password": ...}
      |       -> DB.verify_user() -> {"type": "ok", "username": ...}
      |                                         |
      v                                         v
  AUTHENTICATED (username is now known)
      |  {"type": "message", "text": ...}
      |       -> echo back for now; Phase 3 will route to recipient
      |
      |  {"type": "quit"}  or  connection drops
      -> close

Apos autenticação recebe a chave do cliente e armazena no database.py a chave publica
adiciona à lista de users ativos


## Client

Tem duas threads:

A thread principal lê input do utilizador; uma thread de background recebe mensagens do servidor. O threading.Event() serve de sinal de paragem coordenado entre as duas — é um padrão importante para evitar que o programa fique "preso" após desligar.

**separação auth_flow / chat_loop**
A autenticação é síncrona e sem background thread — precisa de request/response estrito. O receive thread só arranca depois do login ter sido bem-sucedido. O getpass.getpass esconde a password no terminal (não aparece enquanto se escreve).

CHANGES FROM PHASE 1:
  - Before entering the chat loop, the client presents a menu:
    [1] Register   [2] Login
  - All messages are now JSON (send_json / recv_json)
  - The receive thread handles typed messages {"type": "message", ...}
    as well as error and ok responses
  - After login, the chat loop sends {"type": "message", "text": ...}

COMMAND REFERENCE (in chat loop):
  /quit       — disconnect gracefully
  /connect    - conecta a outro user e trocam chaves publicas
  /msg <destinatario> <texto> encripta e envia hex para o destinatario (requere uma chave publica associada ao destinatario na base de dados, se não existir sugere um /conncet <destinatario> primeiro)

  - Messages now carry a `to` field required by the server router.


## Protocol (framing)

WHY THIS EXISTS:
  TCP is a stream protocol — it has no concept of "message boundaries".
  If the server sends "Hello" and "World" back-to-back, the client might
  receive "HelloWorld" or "Hel" + "loWorld" depending on buffering.
 
  Solution: length-prefix framing.
  Every message is sent as:
    [4 bytes: length of payload as big-endian uint32] [payload bytes]

Nota : quando adicionarmos as cifras, o único sítio a tocar é aqui — send_message encripta antes de enviar, recv_message desencripta depois de receber. O resto do código não muda.

WHY JSON: We need structured messages now that the protocol has multiple
    message types (register, login, chat, error...). JSON is human-readable
    for debugging, and trivially extensible — adding a new field to a message
    type doesn't break anything.

    All higher-level code should use send_json/recv_json, NOT send_message/recv_message
    directly. The raw string functions stay for internal use and testing.

**HANDLER DE AUTENTICADOR**

adicionados send_json / recv_json:
O framing de bytes da Fase 1 não mudou. Apenas adicionámos uma camada acima: serializar/deserializar JSON. Isto é importante — tens um contrato claro: a camada de transporte lida com bytes, a camada de protocolo lida com dicts. Nas fases seguintes, quando adicionares cifra, ela vai entrar entre estas duas camadas.

## Database:

Utilizamos SQLite


Toda a lógica de persistência está aqui e em mais lado nenhum. O server.py nunca toca em SQL. Decisões chave:

scrypt para hashing — é memory-hard, resiste a brute-force com GPUs;

sal aleatório por utilizador — impede ataques de rainbow table;

hmac.compare_digest na verificação — evita timing attacks (sem isto, um atacante poderia medir o tempo de resposta para inferir se a password está "quase certa");

threading.Lock() nos writes — SQLite com múltiplas threads precisa disto

**estrutura da db**

- username is the primary key (unique identifier per the spec)
          - password_hash stores "salt_hex:hash_hex"
          - created_at is stored as ISO8601 text (SQLite has no native datetime)
          - Future tables (messages, public_keys) will reference username via FK

**encriptação**

Hash a plaintext password with a fresh random salt using scrypt from the `cryptography` library.

**Na fase 3**
criar uma tabela para as chaves publicas

- > Returns a string in the format "salt_hex:hash_hex" suitable for storage.


## Crypto.py:

Módulo central de toda a lógica de cripto. Nem o cliente nem o servidor devem importar diretamente da biblioteca cryptography — usam estas funções.

Assim a auditoria de segurança resume-se a analisar um único ficheiro.

**generate x...key**:

 Gera um par de chaves X25519 efémero.

    Retorna:
        (private_key, public_key_bytes) — a chave privada fica em memória,
        os bytes da pública são serializados em formato Raw (32 bytes)
        prontos para enviar pela rede.

    PORQUÊ EFÉMERO: cada sessão gera um par novo. Se uma chave privada
    for comprometida no futuro, não compromete sessões passadas
    (contribui para forward secrecy, uma das valorizações do enunciado).

**derive_shared_secret**

Executa ECDH com a chave privada local e a chave pública do par, depois passa o resultado pelo HKDF para obter 32 bytes de material
de chave uniforme.

PORQUÊ HKDF E NÃO O OUTPUT DIRETO DO ECDH: 
O ponto de curva resultante do ECDH tem estrutura matemática que reduz a entropia efetiva. O HKDF "limpa" essa estrutura
e produz bytes uniformemente distribuídos — requisito para AES.

Tem agora as funções de cifrar e decifrar uma mensagem, utiliza a chave pulica e verifica integridade do Selo, se tiver sido mexida a mensagem alterada não é passada


## PLANEAMENTO DO PROJETO:

Phase 1: Basic Communication. Establish a simple TCP connection where the client sends text and the server echoes it back **esta ta feita**
.
Phase 2: Identity & Registry. Implement a way for clients to "register" with the server using a unique ID **tbm ta feita**
.
Phase 3: The Handshake. Implement a protocol where two clients exchange keys through the server to establish a secure channel**tbm ta feita**
.
Phase 4: E2EE Messaging. Encrypt messages on the sender's client and decrypt them only on the receiver's client
.
Phase 5: Persistence & Robustness. Ensure the server can restart without losing user data and handle unexpected client disconnections
.
Phase 6: Enhancements (Valorizações). Choose at least one advanced feature like Offline Messages, Group Chats, or Forward Secrecy
.


## ESTADO ATUAL DO PROJETO:

temos uma base de dados de users a oferecer persistencia já de utilizadores, aqui as passwords são guardadas codificadas atraves de sal da cryptography, só existe acesso à hash da password, nunca ao plain text.

temos outra base de dados para as public keys, com um user associado.
/connect -> troca de chaves é efetuda
/msg (depende do /connect de cada lado primeiro. ex: se o bob der "/connect alice" e dps tentar "/msg alice ola" vai falhar pois a alice tem de fazer /connect bob primeiro) **corrigir isto acho eu**

a fazer: obrigar a atualização da chave depois de x mensagens/ x tempo;
interface grafica (???)

## COMO RODAR:

criar um virtual environment e instalar la os packages (acho q é só cryptography) ajuda

# Terminal 1
python server/server.py

# Terminal 2
python client/client.py

# Terminal 3 (para testar múltiplos clientes em simultâneo)
python client/client.py

# Se der erro de address already in use:
kill $(lsof -t -i :9000) 