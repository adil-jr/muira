# 2. Design criptográfico

- Status: **Proposta** (a ser revisada pelo humano antes da Fase 1)
- Data: 2026-11-01
- Idioma: tradução fiel do original em inglês (2026-11-02), sem mudança de conteúdo

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
DEK embrulhada = AES-256-GCM(KEK, nonce, DEK,       AAD = versão do formato ‖ parâmetros do KDF)
blob do registro = AES-256-GCM(DEK, nonce, plaintext, AAD = ID do registro)
```

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

### AES-256-GCM

- `crypto/aes` + `crypto/cipher.NewGCM`, tag padrão de 16 bytes.
- Um **nonce aleatório de 12 bytes** novo de `crypto/rand` para cada
  cifragem. O NIST SP 800-38D limita o uso de nonces aleatórios a 2^32
  cifragens por chave, muito além do que um cofre pessoal faz; a rotação da
  própria DEK está fora do escopo do MVP.
- **AAD dos registros**: o ID do registro, de modo que um ciphertext copiado
  para outro registro falha ao decifrar.
- **AAD da DEK embrulhada**: a versão do formato e os parâmetros do KDF
  codificados (incluindo o salt), de modo que adulterar os metadados faz a
  autenticação falhar em vez de enfraquecer o KDF silenciosamente.

### Formato do blob

Todo blob cifrado começa com um byte de versão do formato:

```
versão (1 byte) ‖ nonce (12 bytes) ‖ ciphertext ‖ tag GCM (16 bytes)
```

A versão `0x01` é o formato descrito aqui. Versões desconhecidas são
rejeitadas com um erro que não contém material de chave. Uma mudança futura
de formato incrementa o byte e adiciona um caminho de migração.

### Testabilidade

- Uma função não exportada recebe o **nonce como argumento explícito**, para
  que os vetores de resposta conhecida possam ser conferidos byte a byte.
- A API exportada **sempre** gera o nonce por conta própria; quem chama nunca
  pode fornecer um.
- Os parâmetros do Argon2 são **injetados** (um valor `Params`). Com `go test
  -short`, os testes usam parâmetros baratos (por exemplo, `t=1, m=64 KiB,
  p=1`). O padrão de produção é uma constante separada que os testes nunca
  alteram; um teste fora do modo short confere que o padrão é igual à tabela
  acima.

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

## Questões em aberto para revisão

1. O AAD dos registros também deveria vincular o cabeçalho do blob (byte de
   versão), para descartar um downgrade futuro entre versões de formato?
   Proposta: AAD = `versão ‖ ID do registro`.
2. O ID do registro usado como AAD deveria ser o nome visível ao usuário ou
   um ID interno aleatório (renomear um registro então não exigiria
   recifrar)?
