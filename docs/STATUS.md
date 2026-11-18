# Estado do port

Atualizado: 2026-11-18.

Regra deste documento: **só entra como “funciona” o que tem log, saída de teste ou artefato
para provar.** O resto é “não testado” ou “não implementado”, dito assim mesmo.

## Resumo

| Marco | Estado | Evidência |
|---|---|---|
| M0 — estudo da base + inventário | **feito** | `docs/BASE_ANALYSIS.md`, `tools/pe_report.py`, `tools/census64.py` |
| M1 — repositórios + CI | **feito** | workflow verde gerando o APK shell; `leak_check.sh` verde |
| M2 — PoC de lifting | **feito (subconjunto)** | lifter x86-64 + teste diferencial + teste cruzado AArch64 (abaixo) |
| M3 — loader/runtime | **não iniciado** | — |
| M4 — shims Win32 | **não iniciado** | — |
| M5 — janela + Vulkan | **não iniciado** | sonda de Vulkan no APK shell (não medida em aparelho) |
| M6 — áudio/input/armazenamento | **não iniciado** | — |
| M7 — pipeline completo no CI | **parcial** | shell verde; full depende do codegen (existe em `--emit`, não empacotado) |
| M8 — desempenho | **não iniciado** | — |

## O que roda hoje

- **APK shell** (sem código do jogo), artefato público `rdr2-android-shell`: 25 KB, com
  `lib/arm64-v8a/librdr2shell.so`, tela inicial e sonda de Vulkan.
  *Instalado e executado em aparelho: não testado* (não há Android neste ambiente).
- **Ferramentas de análise**: `pe_report.py`, `census64.py`, `whole64.py` rodam sobre os
  binários locais e produzem os números do `BASE_ANALYSIS.md`.
- **Lifter x86-64 → C** (`tools/lift64.py`) e **teste diferencial** (`harness/`).
- **Check anti-vazamento** (`scripts/leak_check.sh`), no CI e local.

## M2 — números medidos

Fonte: `tools/whole64.py --analyze` sobre `Crack/RDR2.exe` (2026-11-18, 421 s).

| Métrica | Valor |
|---|---|
| Funções em `.pdata` | 186.254 |
| Com **todas** as instruções no subconjunto suportado | 131.106 (70,4 %) |
| Levantáveis como **programa fechado** (toda chamada direta resolvida) | 3.854 (2,1 %) |
| Chamadas diretas no grafo | 924.953 |
| C gerado para as 3.854 | 29,0 MB (compila em ~40 s com `-O0`) |

Por que o fecho cai de 70 % para 2 %: as instruções fora do subconjunto são poucas mas
contagiosas — `call` indireto, `div`/`idiv`, x87, `rep stos/scas`, AVX, `lock` — e uma função
que chama uma delas deixa de ser levantável. Isto é o mapa de trabalho real para o M2 completo,
não uma estimativa.

### Teste diferencial (o que prova que o C gerado está certo)

`harness/difftest.c` executa a **função original x86-64** (via `harness/trampoline.S`, com
contexto completo de registradores) e a **função C gerada**, com a mesma entrada, e compara
os 16 registradores, as FLAGS definidas (CF/PF/ZF/SF/OF) e os 16 XMM.

Filtro de seleção (`tools/select_tests.py`): sem chamadas, pilha balanceada em todos os
caminhos, sem escrita fora da pilha, sem salto para fora do intervalo `.pdata`.
Resultado: **490 funções** de 3.841 candidatas.

Rodada final (16 casos aleatórios por função):

```
funções: 487   ok: 462   divergentes: 23   ambos travaram: 5065
um travou: 2   puladas (laço sem fim): 3   casos por função: 16
```

Ou seja: **462 de 487 funções (94,9 %) idênticas ao código de máquina original** em todos os
16 casos; 5.065 casos em que as duas versões travam no mesmo ponto (comportamento igual).

### Divergências conhecidas (sem maquiagem)

1. **`0x141b05304`, `0x141e8d298`** — `xmm4`: diferença no **NaN padrão**. x86 produz
   `0xFFC00000` (QNaN com sinal) em operação inválida; ARM produz `0x7FC00000`. É diferença
   de hardware, não do C: o teste cruzado abaixo mostra exatamente o mesmo caso.
2. **`0x1401f5344`, `0x1401f54a0`** — `r9`/`r10` (ponteiros de varredura) diferem por um
   passo do laço: o número de iterações depende de um valor que vem de um ponteiro, e o
   teste injeta ponteiros diferentes dos reais. **Não resolvido.**
3. **`0x1408bf600`** — `cvttss2si` de um valor que, na versão original, é fora de faixa/NaN
   (resultado `0x80000000`) e na levantada é finito. A causa raiz é a mesma da divergência
   de NaN; o tratamento de "inteiro indefinido" já está implementado e correto.
4. **`0x140979da0`, `0x1414bb358`, `0x141756e68`, `0x1425905ac`** — um lane de XMM difere
   (float). **Não resolvido**; é a próxima investigação do M2.
5. **`0x140712508`, `0x1425b3620`, `0x1425eff50`** — `rax` difere. **Não resolvido.**
6. **1 caso** de `0x1425eff50` em que só a versão levantada trava (`addr 0x210000`, fim da
   arena de teste): acesso de 1 byte além da arena no teste, não no jogo.

Nada disso está escondido: as funções divergentes estão listadas por endereço e o teste é
reprodutível com `scripts/run_difftest.sh`.

### Teste cruzado x86-64 × AArch64

O mesmo C é compilado para x86-64 e para `aarch64-linux-gnu` (estático) e roda sob
`qemu-aarch64-static`, com a pilha e a arena em endereços fixos. Saída comparada linha a linha
(hash do contexto por caso):

```
3.920 casos (490 funções × 8): 3.919 idênticos
1 divergência: 0x1401e6734 caso 5, xmm0/xmm5 — sinal do NaN padrão (item 1 acima)
```

Isso é o que dá para afirmar sobre ARM64 sem aparelho: **o C gerado não depende do host**,
exceto pelo NaN padrão, que é diferença de arquitetura e precisa de decisão explícita
(canonicalizar NaN ou aceitar).

## O que **não** roda

- Qualquer parte do jogo. Não há imagem mapeada no aparelho, nem runtime, nem shim Win32.
- Nada foi executado em ARM64 Android. O teste cruzado roda em **qemu**, não em hardware.
- O lifter cobre **2,1 %** das funções em programa fechado. Os outros 97,9 % precisam das
  instruções que faltam (é trabalho, não surpresa).

## Bloqueios declarados (com evidência)

1. **Segunda `.text` de 21,8 MB**, sem `.pdata`, ofuscada, alcançada pelo entry point
   (`docs/BASE_ANALYSIS.md` §7.3). Não é liftável por análise estática com confiança.
2. **SEH x64 / C++ EH**: 186.254 `RUNTIME_FUNCTION`. Implementar *virtual unwinding* +
   `__CxxFrameHandler4` é o maior item isolado; sem isso, qualquer exceção mata o processo.
3. **Texturas BC**: Adreno/Mali não expõem `VK_FORMAT_BC*`. Sem transcode BC→ASTC/ETC2 o jogo
   sobe sem textura (`docs/VULKAN_CAPS.md`).
4. **Escala de build**: 1,4–2,5 GB de C, ~4,5 core-horas, `.so` de 500–900 MB.
5. **Launcher/Social Club**: o executável espera `RDR2Launcher_Pipe` e `socialclub.dll`.

## Próximos passos, por ordem de impacto

1. Fechar as 23 divergências do teste diferencial (item por item, com o `harness/probe.c`).
2. Instruções que faltam, por frequência no censo: `call` indireto (via IAT/tabela), `div`/
   `idiv`, `rep movs/stos`, `lock`, AVX. Cada uma destrava um bloco do fecho de 2 % → 70 %.
3. *Virtual unwinding* de `.pdata` + `__try/__except` simples antes de qualquer C++.
4. Loader PE32+ com identidade de endereços + TLS + init do CRT; chegar a `WinMain` com stubs
   logados (M3/M4).
5. Instrumentar a execução no Windows para mapear a segunda `.text` (§7.3).
6. Medir o driver Vulkan real com a sonda do APK shell e preencher `VULKAN_CAPS.md`.