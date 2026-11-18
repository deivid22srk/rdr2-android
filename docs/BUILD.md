# Como construir

## Sem a cópia do jogo (APK shell)

É o que roda no CI em todo push. Não precisa de nada do jogo.

```
./gradlew assembleDebug -PndkVersion=27.2.12479018
# app/build/outputs/apk/debug/app-debug.apk
```

Requer JDK 17, Android SDK com `platforms;android-34`, `build-tools;34.0.0`, `cmake;3.22.1`
e `ndk;27.2.12479018`. O mesmo comando roda no GitHub Actions
(`.github/workflows/build.yml`, job `apk`, variante `shell`).

O APK contém: a tela inicial, a **sonda de Vulkan** (JNI) e nada derivado do jogo. É o
artefato público.

## Ferramentas de análise (não precisam de Android)

Python 3.10+ com `pefile` e `capstone`:

```
pip install pefile capstone

export RDR2_GAME_DIR=/caminho/para/a/sua/copia   # nunca hardcode esse caminho

python3 tools/pe_report.py  "$RDR2_GAME_DIR/Crack/RDR2.exe" > /tmp/pe.json
python3 tools/census64.py   "$RDR2_GAME_DIR/Crack/RDR2.exe" 0 /tmp/census.json
python3 tools/whole64.py    "$RDR2_GAME_DIR/Crack/RDR2.exe" --analyze --report /tmp/whole.json
```

Todos leem o binário e escrevem relatórios. Nenhum deles copia bytes do jogo para dentro do
repositório.

## Teste diferencial (M2)

Prova que o C gerado tem a mesma semântica do x86-64 original. Roda no host x86-64:

```
python3 tools/whole64.py "$RDR2_GAME_DIR/Crack/RDR2.exe" --emit /tmp/gen --max 3000
python3 tools/select_tests.py "$RDR2_GAME_DIR/Crack/RDR2.exe" --out /tmp/gen/tests.h --max 400
clang -O0 -I runtime -I /tmp/gen -o /tmp/difftest \
      harness/difftest.c harness/trampoline.S /tmp/gen/lifted.c
/tmp/difftest "$RDR2_GAME_DIR/Crack/RDR2.exe" 8
```

Saída esperada: uma linha por divergência (não deve haver) e o resumo com funções, casos e
falhas. O teste mapeia a imagem em `0x140000000`, então precisa de um processo x86-64 livre
nesse endereço (o normal).

## APK full (com o código do jogo)

Não é feito à mão no repositório público. O fluxo é:

1. Na máquina do dono, com a cópia do jogo:
   `tools/whole64.py ... --emit gen --max N` gera `gen/lifted.c`, `gen/lifted.h`.
2. Empacotar `gen/` + relatórios em `codegen.tar.zst` e publicar numa **release do
   repositório privado** `rdr2-codegen` (tag em `GEN_TAG`).
3. No GitHub, `workflow_dispatch` com `variant=full`. O job exige
   `github.repository_owner == deivid22srk` e o segredo `GEN_TOKEN`; baixa o tar, compila e
   publica o APK **na release do repositório privado**.

Configuração necessária no repositório público:

| Nome | Tipo | Valor |
|---|---|---|
| `GEN_REPO` | variable | `deivid22srk/rdr2-codegen` |
| `GEN_TAG` | variable | tag da release com `codegen.tar.zst` |
| `GEN_TOKEN` | secret | PAT fine-grained com `contents:read` (baixar) e `contents:write` no repo privado (publicar o APK) |

Sem esses valores o workflow continua verde no modo shell. Um PR de fork não recebe segredo
e o job full é recusado explicitamente.

## Cache e tempo

- Gradle: `gradle/actions/setup-gradle` (wrapper com validação desligada; a distribuição é
  fixada por URL em `gradle/wrapper/gradle-wrapper.properties`).
- NDK/CMake: instalados pelo `android-actions/setup-android`, versões fixas.
- O codegen tem cache de objeto próprio (hash de fonte + flags), que não vai para o CI —
  cada run recompila do zero. É o custo dominante do build full.

## Limites do CI público (medidos, não estimados)

Runner `ubuntu-latest`: 4 vCPU, 16 GB RAM, ~14 GB de disco livre, 6 h por job. O build shell
leva ~2 min. O full é estimado em 60–90 min de compilação mais link, com 1,4–2,5 GB de C —
ver `docs/BASE_ANALYSIS.md` §7.2. Se não couber, o plano é dividir o codegen em jobs de
matriz com cache de objetos.
