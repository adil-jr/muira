# 2. Design criptográfico

- Status: **Aceita** (2026-11-02, revisada pelo humano no início da Fase 1)
- Data: 2026-11-01 (proposta) · 2026-11-02 (aceita)
- Idioma: pt-BR. Traduzida do original em inglês em 2026-11-02; o conteúdo
  mudou na aceitação (codificação do AAD, ID do registro, limites de
  parâmetros, erros e questões resolvidas)

## Contexto

O muira guarda segredos num arquivo local protegido por uma única senha
mestra. Precisamos de um design que:

- resista a força bruta offline contra o arquivo do cofre;
- permita trocar a senha mestra sem recifrar todos os registros;
- detecte adulteração e troca de registros;
- permita evoluir o formato em disco;
- seja testável contra vetores oficiais de resposta conhecida, não contra si mesmo.

Só são permitidas primitivas da biblioteca padrão do Go e de
`golang.org/x/crypto`, e só dentro de `internal/crypto`.

## Decisão

### Envelope encryption

```
senha mestra ──Argon2id(salt, params)──▶ KEK (32 bytes)
crypto/rand ───────────────────────────▶ DEK (32 bytes)
DEK embrulhada   = AES-256-GCM(KEK, nonce, DEK,       AAD = enc("muira/dek", versão, t, m, p, keyLen, salt))
blob do registro = AES-256-GCM(DEK, nonce, plaintext, AAD = enc("muira/record", versão, ID do registro))
```

`enc(...)` é a codificação length-prefixed descrita em "Codificação do AAD".

- A **KEK** (key-encryption key) é derivada da senha mestra com Argon2id e
  nunca é armazenada.
- A **DEK** (data-encryption key) são 32 bytes aleatórios de `crypto/rand`,
  gerados uma vez no `init`, e armazenados apenas embrulhados pela KEK.
- Os registros são cifrados com a DEK.
- A **rotação de senha** deriva uma nova KEK (salt novo) e reembrulha apenas a
  DEK. Os registros não são tocados.
- **Verificação da senha**: a senha está correta se, e somente se, a DEK
  embrulhada é decifrada (a tag do GCM confere). Não há um hash verificador
  separado, que seria mais um alvo de ataque offline e mais uma coisa a
  manter sincronizada.

### Parâmetros do Argon2id

RFC 9106, seção 4, segunda opção recomendada (para ambientes com memória
limitada):

| Parâmetro | Valor |
|---|---|
| Iterações `t` | 3 |
| Memória `m` | 64 MiB (65536 KiB) |
| Paralelismo `p` | 4 |
| Salt | 16 bytes aleatórios (`crypto/rand`), novo a cada rotação |
| Saída | 32 bytes |

Implementação: `argon2.IDKey` de `golang.org/x/crypto/argon2` (Argon2
versão 0x13).

Os parâmetros e o salt são **gravados nos metadados do cofre** no `init` e a
cada rotação, e são **sempre lidos dos metadados** ao desbloquear. Os padrões
de produção só são usados ao criar material de chave novo, então os padrões
podem ser elevados no futuro sem quebrar cofres existentes.

#### Validação dos parâmetros

Os parâmetros são lidos dos metadados **antes** de qualquer autenticação,
então um arquivo adulterado poderia pedir um KDF absurdo (negação de
serviço) ou fraco. Há duas checagens:

- `Validate`, aplicada em **toda** derivação (estrutural + anti-DoS):
  - `KeyLen == 32`;
  - `1 ≤ t ≤ 64`;
  - `p ≥ 1`;
  - `8·p ≤ m ≤ 1 GiB (1048576 KiB)`, com `8·p` calculado em 32 bits
    (`p` é `uint8`, e em 8 bits a multiplicação daria a volta a partir de
    `p = 32`).
- `ValidateNew`, aplicada só ao criar material de chave novo (`init` e
  rotação): `Validate` mais o piso da OWASP para Argon2id, `m ≥ 19456 KiB`
  e `t ≥ 2`.

Parâmetros que passam em `Validate` mas foram adulterados continuam sendo
pegos: eles fazem parte do AAD da DEK, então a decifragem falha.

Os padrões ficam numa função, `DefaultParams()`, que devolve uma cópia do
valor (Go não tem constante de struct); assim nenhum chamador consegue
alterá-los.

### AES-256-GCM

- `crypto/aes` + `crypto/cipher.NewGCM`, tag padrão de 16 bytes.
- Um **nonce aleatório de 12 bytes** novo de `crypto/rand` para cada
  cifragem. O NIST SP 800-38D limita o uso de nonces aleatórios a 2^32
  cifragens por chave, muito além do que um cofre pessoal faz; a rotação da
  própria DEK está fora do escopo do MVP.
- **AAD dos registros**: rótulo de domínio, versão do formato e ID do
  registro, de modo que um ciphertext copiado para outro registro falha ao
  decifrar.
- **AAD da DEK embrulhada**: rótulo de domínio, versão do formato, parâmetros
  do KDF e salt, de modo que adulterar os metadados faz a autenticação falhar
  em vez de enfraquecer o KDF silenciosamente.
- A API exportada só oferece `SealRecord`/`OpenRecord` e
  `WrapDEK`/`UnwrapDEK`, que montam o AAD internamente; não existe um
  `Seal(key, pt, aad)` genérico, então o vault não tem como montar um AAD
  errado.

`NewSalt`, `NewDEK` e `NewRecordID` retornam `[]byte` sem `error`, porque
desde o Go 1.24 o `crypto/rand.Read` não falha (se a fonte falhar, o programa
aborta); não há `io.Reader` injetado. O nonce explícito existe só na função
interna usada pelos KATs.

### Codificação do AAD

Cada campo é codificado como `uint32 big-endian com o tamanho ‖ bytes`, e os
campos são concatenados. Como o tamanho vem antes dos bytes, o parse é
determinístico e a codificação é **injetiva**: listas de campos diferentes
nunca produzem o mesmo AAD (por exemplo, `["ab","c"]` ≠ `["a","bc"]` e
`[]` ≠ `[""]`). Uma concatenação simples permitiria essas colisões.

O primeiro campo é sempre um **rótulo de domínio** fixo, que separa os dois
contextos de uso: um blob selado num contexto nunca autentica no outro,
mesmo que a mesma chave fosse usada nos dois.

| Contexto | Campos, em ordem |
|---|---|
| DEK embrulhada | `"muira/dek"`, versão (1 byte), `t` (u32 BE), `m` em KiB (u32 BE), `p` (1 byte), `keyLen` (u32 BE), salt (16 bytes) |
| Registro | `"muira/record"`, versão (1 byte), ID do registro (16 bytes) |

### ID do registro

O ID do registro são **16 bytes aleatórios de `crypto/rand`**, gerados
dentro de `internal/crypto` (o depguard confina `crypto/rand` a esse
pacote). Ele é a chave do registro no bbolt e entra no AAD. O nome e o
serviço visíveis ao usuário ficam **só dentro do payload cifrado**: o
arquivo do cofre não revela quais serviços estão guardados, e renomear um
registro não muda o seu ID.

**Trade-off:** buscar um registro pelo nome exige decifrar todos os
registros, O(n) com custo de AES-GCM. Para um cofre pessoal (centenas de
registros) isso é irrelevante; um índice cego fica para a v2.

### Formato do blob

Todo blob cifrado começa com um byte de versão do formato:

```
versão (1 byte) ‖ nonce (12 bytes) ‖ ciphertext ‖ tag GCM (16 bytes)
```

A versão `0x01` é o formato descrito aqui. Versões desconhecidas são
rejeitadas com um erro que não contém material de chave. Uma mudança futura
de formato incrementa o byte e adiciona um caminho de migração.

O byte de versão do cabeçalho **não** é passado como AAD ao GCM, mas o valor
da versão já está dentro do AAD (segundo campo). Trocar o byte do cabeçalho
só leva a `ErrUnsupportedVersion`, porque a v1 é a única versão aceita; quando
existir uma v2, a versão no AAD impede que um blob de uma versão autentique
como outra.

Ordem das checagens ao abrir um blob:

1. blob vazio → `ErrDecrypt`;
2. versão ≠ `0x01` → `ErrUnsupportedVersion`;
3. tamanho < 1 + 12 + 16 bytes → `ErrDecrypt`;
4. falha do GCM (tag não confere) → `ErrDecrypt`.

### Erros

| Erro | Quando |
|---|---|
| `ErrDecrypt` | senha errada, adulteração, blob truncado ou AAD diferente. **Opaco**: os casos são indistinguíveis de propósito |
| `ErrUnsupportedVersion` | byte de versão desconhecido |
| `ErrInvalidParams` | parâmetros do KDF fora dos limites; embrulhado com o nome do campo |
| `ErrInvalidLength` | chave, salt ou ID do registro com tamanho errado |

Todos são comparáveis com `errors.Is`, e nenhuma mensagem de erro carrega
senha, chave, DEK, salt, nonce ou plaintext.

### Testabilidade

- Uma função não exportada recebe o **nonce como argumento explícito**, para
  que os vetores de resposta conhecida possam ser conferidos byte a byte.
- A API exportada **sempre** gera o nonce por conta própria; quem chama nunca
  pode fornecer um.
- Os parâmetros do Argon2 são **injetados** (um valor `Params`). Com `go test
  -short`, os testes usam parâmetros baratos (por exemplo, `t=1, m=64 KiB,
  p=1`). O padrão de produção vem de `DefaultParams()`, que os testes nunca
  alteram; um teste confere que o padrão é igual à tabela acima.

### Vetores de teste (os valores esperados nunca vêm do nosso próprio código)

Os vetores são commitados em `testdata/` com a fonte registrada ao lado.

**AES-256-GCM: NIST CAVP**
- Arquivo: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip>
  (SHA-256 `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`,
  baixado em 2026-11-01).
- Arquivos: `gcmEncryptExtIV256.rsp` e `gcmDecrypt256.rsp`, seções
  `[Keylen = 256]`, `[IVlen = 96]`, `[Taglen = 128]`. O arquivo de decrypt
  inclui casos `FAIL`, que precisam ser rejeitados.

**Argon2id: implementação de referência (phc-winner-argon2)**
- Repositório: <https://github.com/P-H-C/phc-winner-argon2>, commit
  `f57e61e19229e23c4445b85494dbf7c07de721cb`, arquivo `src/test.c`, o bloco
  `Argon2id` da versão `0x13` (`hashtest(version, t, log2(m KiB), p,
  pwd, salt, hexref, mcfref, Argon2_id)`, saída de 32 bytes). Note que `m` é
  dado como logaritmo na base 2 de KiB (16 → 65536 KiB).
- **Não utilizáveis**: o vetor da seção 5.3 da RFC 9106 e o arquivo
  `kats/argon2id` do repositório definem um `secret` (K) e `associated data`
  (X). O `argon2.IDKey` não expõe essas entradas, então esses vetores não
  podem ser reproduzidos pela API que usamos.

## Consequências

- Desbloquear custa ~64 MiB e uma fração perceptível de segundo, por design;
  os testes precisam injetar parâmetros baratos para continuar rápidos.
- A rotação é barata e atômica (uma escrita nos metadados).
- Um registro de metadados corrompido ou adulterado faz o cofre falhar ao
  desbloquear, em vez de abrir com parâmetros mais fracos.
- Buscar um registro pelo nome decifra todos os registros (O(n)); aceitável
  para o tamanho de um cofre pessoal.

### Limites conhecidos

- **A higiene de memória é de melhor esforço.** Segredos são `[]byte` e são
  zerados com `clear()` após o uso, mas o runtime do Go pode copiar memória
  (GC, crescimento de pilha, conversões para `string` em código de
  terceiros). Não prometemos que segredos nunca permaneçam na memória ou no
  swap.
- **O modo de arquivo 0600 não tem efeito no Windows**; lá o acesso depende
  das ACLs do perfil do usuário.
- **Sem proteção contra malware rodando como o mesmo usuário** (keyloggers,
  leitores de memória, um binário modificado). O modelo de ameaças cobre um
  arquivo de cofre roubado ou copiado, não uma conta comprometida.

## Questões resolvidas

1. *O AAD dos registros também deveria vincular a versão do formato, para
   descartar um downgrade futuro entre versões?* **Sim.** O AAD do registro
   é `enc("muira/record", versão, ID do registro)`, com a codificação
   length-prefixed e o rótulo de domínio descritos acima. A mesma codificação
   vale para o AAD da DEK, que também inclui o salt.
2. *O ID do registro usado como AAD deveria ser o nome visível ao usuário ou
   um ID interno aleatório?* **ID interno aleatório** de 16 bytes, usado
   como chave no bbolt e no AAD. O nome fica só no payload cifrado, e o
   custo é a busca O(n) descrita em "ID do registro".

## Evolução (v2, fora do escopo do MVP)

- **Índice cego com HMAC** para buscar registros pelo nome sem decifrar
  todos.
- **Re-key da DEK**: comando que gera uma DEK nova e recifra todos os
  registros (a rotação de senha do MVP só reembrulha a DEK).
