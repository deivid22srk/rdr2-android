# Estado do port

Atualizado: 2026-11-18.

Regra deste documento: **só entra como “funciona” o que tem log, saída de teste ou artefato
para provar.** O resto é “não testado” ou “não implementado”, dito assim mesmo.

## Resumo

| Marco | Estado | Evidência |
|---|---|---|
| M0 — estudo da base + inventário | **feito** | `docs/BASE_ANALYSIS.md`, `tools/pe_report.py`, `tools/census64.py` |
| M1 — repositórios + CI | **feito** | `build.yml` verde gerando APK shell; `leak_check.sh` verde |
| M2 — PoC de lifting | **em andamento** | lifter x86-64 + teste diferencial em `tools/` (ver abaixo) |
| M3 — loader/runtime | **não iniciado** | — |
| M4 — shims Win32 | **não iniciado** | — |
| M5 — janela + Vulkan | **não iniciado** | sonda de Vulkan no APK shell (não medida em aparelho) |
| M6 — áudio/input/armazenamento | **não iniciado** | — |
| M7 — pipeline completo no CI | **parcial** | shell verde; full depende do codegen (não existe ainda) |
| M8 — desempenho | **não iniciado** | — |

## O que roda hoje

- **APK shell** (sem código do jogo): construído no CI, artefato público
  `rdr2-android-shell`. Contém a tela inicial, a sonda de Vulkan e o carregador JNI.
  *Instalado e executado em aparelho: não testado* (não há Android neste ambiente).
- **Ferramentas de análise**: `pe_report.py`, `census64.py`, `catalog64.py` rodam neste
  ambiente sobre os binários locais e produzem os números do `BASE_ANALYSIS.md`.
- **Check anti-vazamento**: `scripts/leak_check.sh` roda no CI e localmente; falha se
  aparecer PE, `.rpf`, `gen/`, arquivo > 5 MB ou hash de conteúdo do jogo.

## O que não roda

- Qualquer parte do jogo. Não há executável mapeado, nem runtime, nem shim Win32.
- Nada foi executado em ARM64 Android. O teste diferencial do M2 roda no **host x86-64**
  (Linux), comparando o código original com o C levantado — é o que dá para provar aqui.

## Bloqueios declarados (com evidência)

1. **Segunda `.text` de 21,8 MB, sem `.pdata`, ofuscada** e alcançada a partir do entry point
   (`docs/BASE_ANALYSIS.md` §7.3). Não é liftável por análise estática com confiança. Precisa
   de trace de execução para saber o que roda de fato.
2. **SEH x64 / C++ EH**: 186.254 `RUNTIME_FUNCTION`. Implementar *virtual unwinding* +
   `__CxxFrameHandler4` é o maior item isolado; sem isso, qualquer exceção (inclusive
   `std::bad_alloc`) mata o processo.
3. **Texturas BC** no caminho Vulkan: Adreno/Mali não expõem `VK_FORMAT_BC*`. Sem transcode
   BC→ASTC/ETC2 o jogo sobe sem textura. Ver `docs/VULKAN_CAPS.md`.
4. **Escala de build**: 1,4–2,5 GB de C gerado, ~4,5 core-horas de compilação, `.so` de
   500–900 MB. Cabe no limite de 6 h do CI, mas exige sharding; medir antes de prometer.
5. **Launcher/Social Club**: o executável espera `RDR2Launcher_Pipe` e `socialclub.dll`.
   Sem stubs de handshake offline o processo não chega ao loop principal.

## Próximos passos, por ordem de impacto

1. Fechar o M2 num subconjunto de instruções (inteiro + SSE escalar) com teste diferencial
   em milhares de casos; medir a fração de funções do RDR2 que o subconjunto cobre.
2. Escrever o *virtual unwinding* de `.pdata` e testar em funções com `__try/__except`
   simples antes de qualquer coisa de C++.
3. Loader de imagem PE32+ com identidade de endereços + `TLS` + init do CRT; chegar a
   `WinMain` com stubs logados (M3/M4).
4. Instrumentar a execução no Windows para mapear a segunda `.text` (§7.3) — é o único
   caminho honesto para saber se ela pode ser substituída por stubs.
5. Medir o driver Vulkan real com a sonda do APK shell e preencher a tabela de
   `VULKAN_CAPS.md`.
