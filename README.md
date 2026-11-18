# RDR2 Android — recompilação estática (x86-64 → ARM64)

Port de **Red Dead Redemption 2 (PC)** para **Android arm64-v8a** por **recompilação estática**:
o código de máquina x86-64 do executável é traduzido para C em tempo de build, compilado para
ARM64 e empacotado num APK. Nada de emulador, nada de JIT em runtime, nada de Box64/FEX/Winlator.

Base arquitetural: [RunnerRecompiled](https://github.com/singlemate/RunnerRecompiled)
(Mirror's Edge, x86 de 32 bits → C → ARM64), estudado e estendido em
[`docs/BASE_ANALYSIS.md`](docs/BASE_ANALYSIS.md).

> **Este repositório não contém material do jogo.** Nem o executável, nem dados (`.rpf`),
> nem código gerado a partir deles. Para usar o port você precisa de **uma cópia legítima
> do jogo, sua**, e o build é feito a partir dela. O resultado contém código derivado do
> jogo: **não publique nem compartilhe**.

## Estado

O que já existe e o que falta, com evidência, está em [`docs/STATUS.md`](docs/STATUS.md).
Resumo: a análise do binário e o pipeline de build estão de pé; o runtime e o grafismo
ainda não. Nada foi executado em Android real até agora — o documento diz exatamente onde
cada coisa para.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `tools/` | Leitor PE32+, inventário, catálogo de funções, lifter x86-64 → C, teste diferencial |
| `runtime/` | Runtime de execução: memória, carregador, Win32, threads, exceções |
| `app/` | App Android (shell e build full), sonda de Vulkan |
| `gen/` | Código gerado. **Não versionado** (vem do repositório privado) |
| `docs/` | Análise, arquitetura, Vulkan, estado, build |
| `.github/workflows/build.yml` | APK shell (público) e APK full (release privada) |

## Build

Ver [`docs/BUILD.md`](docs/BUILD.md). O caminho normal é o CI: push em `main` gera o APK
shell como artefato público; `workflow_dispatch` com `variant=full` (só o dono, com o
segredo `GEN_TOKEN`) gera o APK com código do jogo e o publica numa release do
repositório **privado** `rdr2-codegen`.

## Licença

Código original deste repositório: MIT (`LICENSE`). *Red Dead Redemption 2* é marca da
Rockstar Games. Este é um projeto de fã, não afiliado nem endossado pela Rockstar.
