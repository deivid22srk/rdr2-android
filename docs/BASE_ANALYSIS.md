# Análise da base: RunnerRecompiled e os executáveis do RDR2

Data: 2026-11-18. Este documento responde, com evidência, o que o projeto base faz e o que
muda para o Red Dead Redemption 2. Tudo que está aqui foi lido no código do
[RunnerRecompiled](https://github.com/singlemate/RunnerRecompiled) (clone em `/tmp/rr`,
`README.md`, `pc/LIFTER-DESIGN.md`, `pc/BUILDER.md`, `pc/SELFBUILD.md`, `pc/tools/*.py`,
`pc/runtime/*.c`) ou medido nos binários locais. Nada foi suposto sem dizer que é suposição.

Comandos usados para medir os binários (não versionados):

```
python3 tools/pe_report.py   "$RDR2_GAME_DIR/Crack/RDR2.exe"
python3 tools/census64.py    "$RDR2_GAME_DIR/Crack/RDR2.exe" 0 /tmp/census.json
```

---

## 1. Lifter, técnica e ISA de entrada

**Técnica.** Recompilação estática própria: cada função x86 vira uma função C que opera sobre
um contexto de CPU (`X86Ctx`), e o C é compilado para ARM64 pelo clang do NDK. Não há
interpretador nem JIT no aparelho. O desmontador é o LLVM MC (`libLLVM-23.dll` do llvm-mingw)
chamado por `ctypes`; o fluxo de controle (`jcc`, `call` rel32, `jmp [reg*4+disp32]`) é
decodificado à mão em `pc/tools/x86cfg.py` para não depender de heurística do desmontador.

**ISA de entrada: x86 de 32 bits (PE32/i386), exclusivamente.** A prova está em
`pc/tools/pe32.py`:

```python
machine, nsec, ... = struct.unpack_from("<HHIIIHH", data, pe + 4)
if machine != 0x14C:
    raise ValueError(f"machine {machine:#x} is not i386")
...
if struct.unpack_from("<H", data, opt)[0] != 0x10B:
    raise ValueError("not PE32")
```

Ou seja: `IMAGE_FILE_MACHINE_I386` (0x14C) e `PE32` (0x10B). Qualquer PE32+ é rejeitado na
porta de entrada. Não existe, no repositório, caminho para x86-64, REX, `r8..r15`,
endereçamento RIP-relativo, AVX/VEX ou SEH por tabela (`.pdata`). O README e o
`LIFTER-DESIGN.md` falam só de Mirror's Edge (GOG, 2009, 32 bits).

**Números do base (medidos pelo próprio projeto, `LIFTER-DESIGN.md`):**

| Métrica | Valor |
|---|---|
| Funções alcançáveis | 178.605 |
| Instruções alcançáveis | 5,73 milhões |
| Mnemônicas distintas | 193 (52 cobrem 99 %) |
| Cobertura do lifter | 178.486 / 178.605 = 99,93 % |
| C gerado | ≈ 640 MB, 151 shards |
| Binário final | `me_pc.exe` 119 MB (PC), `libmepc.so` ≈ 230 MB (arm64) |
| Tempo de lifting | 73 s (151 shards) |
| Tempo de compilação | 259 s em 20 threads |

## 2. Organização, particionamento e compilação do código gerado

Pipeline (`pc/tools/`):

1. `catalog.py` + `pe32.py` + `x86cfg.py` → `catalog.json` (funções, blocos, dono de cada
   byte de `.text`, tabelas `switch`, sementes). Sementes: entry point, alvos de `call`
   direto, `.reloc` apontando para `.text` (vtables, ponteiros de função, tabelas de
   unwinding), exports (para DLLs) e a tabela SafeSEH do Load Config.
2. `lift.py` → C por função. Registradores em variáveis locais C, `ctx` só em volta de
   chamadas; flags preguiçosas (`X86Flags` guarda operação e operandos, `x86_cc()` resolve);
   x87 em `double` com controle de precisão de 24 bits, SSE em vetores, MMX separado do x87.
3. `gen_module.py` → `shard_NNN.c` de ~3 MB cada. Cada shard **declara só as funções que
   chama** (cabeçalho mínimo, sem um header gigante), mais `dispatch_<módulo>.c`, uma tabela
   ordenada `{endereço de convidado, função}` para chamadas indiretas.
4. `build_pc_runtime.py` → compila em paralelo (clang do NDK para arm64), com cache de objeto
   por SHA-256 de fonte + headers + flags, `-O2 -fwrapv -ffp-contract=off`. Funções enormes e
   frias recebem `-O0` (`COLD_HUGE` em `gen_module.py`): uma delas sozinha levava 2–3 min de
   clang em todo build.
5. `apk_pack.py` → injeta o `.so` no APK shell e assina **sem Gradle, sem SDK e sem Java**:
   monta o ZIP, alinha, gera o esquema de assinatura v2 com PKCS#12 lido em Python puro.

O app Android do base **não usa Gradle**: `android/build.ps1` chama `javac`, `d8`, `aapt2` e
`clang` direto. Para este port usamos Gradle (é o que o CI do usuário já usa nos outros ports
e o que o `build.yml` de referência pede), mas o princípio é o mesmo: o código gerado entra
como objetos/`.so` e o APK shell não muda.

## 3. Runtime: memória, imports, TLS, exceções, threads

`pc/runtime/rt_core.c` (+ `x86rt.h`), ~38 KB:

- **Memória do convidado:** um único espaço plano de 32 bits a partir de `x86_mem_base`
  (4 GB reservados no arm64). Endereço de convidado = deslocamento. Regiões reservadas em
  granularidade de 64 KB (`RT_GRANULE`), páginas de 4 KB (`RT_PAGE`), com estado por página
  (commit/reserve/proteção) imitando `VirtualAlloc`/`VirtualProtect`. A imagem é mapeada na
  `ImageBase` (0x400000), então **relocações não são aplicadas**; a tabela `.reloc` serve só
  para achar ponteiros.
- **Imports:** o carregador de PE resolve exports por base de módulo (a própria imagem + DLLs
  do CRT levantadas com o mesmo lifter + HLE). Cada slot da IAT recebe o endereço da função
  levantada ou de um **thunk HLE** em `0xFE000000` (passo 4). Chamada por IAT =
  `x86_dispatch(ctx, ld32(slot))`. Import não encontrado **para o processo** com o nome.
- **TLS:** 1.088 slots (64 no TEB + 1.024 de expansão), TEB/PEB no formato Windows XP SP3,
  `fs_base` no contexto, `LastError` em `TEB+0x34`.
- **Exceções:** cadeia SEH em `fs:[0]`; `tools/eh.py` lê estaticamente as tabelas do MSVC x86
  (`_except_handler3/4`, `__CxxFrameHandler3`, funclets de `catch`/`__except`) e transforma
  cada continuação em um *resume point*. Em runtime `x86_resume_*` + `longjmp` retomam o
  frame. É uma solução específica de 32 bits.
- **Threads:** `CreateThread` cria `RtThread` com TEB e pilha de convidado próprios;
  sincronização em `rt_sync.c` (eventos, mutexes, semáforos, SRW/CRITICAL_SECTION) sobre
  pthread/futex do host.
- **Falha:** `rt_host_android.c` instala handler de sinal e traduz o PC do host para o
  endereço de convidado antes de logar.

## 4. Camada Win32 (o que é emulado)

`rt_kernel32.c` (~130 funções KERNEL32 + `CommandLineToArgvW`), `rt_files.c` (arquivos,
`Find*`, atributos), `rt_user32.c` (janela, mensagens, timers), `rt_stubs.c` (stubs genéricos
com ABI deduzida do nome decorado MSVC — usados pelo editor wxWidgets embutido),
`rt_kernel32.c` registra também SHELL32, WINMM e winsock (`ws2_32`) em tabelas HLE.
DirectInput 8 (`rt_dinput.c`) e XInput 1.3 por ordinal (#2/#3) também são HLE. Áudio é
**OpenAL** (`rt_openal.c`), não XAudio2.

Regra de stub, do próprio projeto: genérico, com contagem de argumentos tirada do nome
decorado, **logado uma vez** na primeira chamada. É exatamente a regra que este port mantém.

## 5. Gráficos, áudio e input

- **Gráficos:** `Direct3DCreate9` → objeto proxy de convidado (vtable de convidados, cada
  método um thunk HLE) → **DXVK Native** (patch próprio em `pc/dxvk/`, zlib) → Vulkan no
  Android, com WSI em `ANativeWindow` (`dxvk_android_set_window`, ver
  `rt_host_android.c`). 17 interfaces, ~320 métodos, 119 deles em `IDirect3DDevice9`; gerados
  por `gen_d3d9_bridge.py`. `Lock/Unlock` usam buffer intermediário porque a memória que o
  DXVK devolve está fora dos 4 GB do convidado.
- **Áudio:** OpenAL Soft nativo; Bink por HLE ou recompilação de `binkw32.dll`.
- **Input:** XInput/DirectInput → JNI para o app Android (gamepad + overlay de toque em
  `android/src/.../TouchPad.java`, `Controller.java`, `InputState.java`).

## 6. Como o shell APK recebe o código e os dados

- **Código:** o APK shell é gerado uma vez e publicado. No PC do usuário, `apk_pack.py` abre
  esse APK, adiciona `lib/arm64-v8a/libmepc.so` (e `libdxvk_d3d9.so`), reescreve o ZIP,
  alinha e assina com a chave pessoal. Nenhum código do jogo passa por servidor.
- **Dados:** dois caminhos. (a) ZIP dos arquivos do jogo, importado pelo app
  (`PcSetup`), com checagem de SHA-256 do executável e preparo das bibliotecas. (b) Com o
  aparelho ligado por USB/Wi-Fi, `device.py` instala o APK e envia os arquivos por
  `adb forward` para um socket local do app (`PcSetup.receive`), que aceita só `adbd` (uid
  shell) e confina tudo em `Binaries`, `Engine` e `TdGame`.
- **Resultado:** o app roda o jogo em processo próprio (`:pc`), com a `Activity` de jogo
  separada da de launcher.

## 7. Diferenças para o RDR2 (o que não se aproveita)

### 7.1 O binário

| | Mirror's Edge (base) | RDR2 (medido) |
|---|---|---|
| Formato | PE32, i386 | **PE32+ AMD64** (`0x8664`, magic `0x20B`) |
| `ImageBase` | 0x400000 | **0x140000000** |
| Imagem | ~30 MB | **117,3 MB** (`SizeOfImage 0x7528000`) |
| `.text` | 21,6 MB | **50,5 MB** + **21,8 MB** numa segunda `.text` |
| Funções | 178.605 | **186.254** só com `.pdata` (+ a segunda `.text`, sem unwind) |
| Instruções | 5,73 M | **12,42 M** medidas (só a primeira `.text`) |
| Mnemônicas | 193 | **663** |
| Relocações | tabela completa | **0 no crack (diretório removido)**, 526.128 no original |
| Exceções | SafeSEH + `fs:[0]` | **`.pdata` + `UNWIND_INFO`** (186.254 registros) |
| TLS | sim | sim (`TLS` dir presente, callbacks em `0x1432BA978`) |
| Imports | centenas, 32 bits | **416 funções em 26 DLLs** (contadas: KERNEL32 176, USER32 80, WS2_32 31, bink2w64 23, bcrypt 20, oo2core 15, …) |

A contagem de instruções saiu de `tools/census64.py` (varredura linear dentro de cada
`[BeginAddress, EndAddress)` de `.pdata` com capstone): 12.423.094 instruções, 49,6 MB
decodificados de 50,5 MB, 33.126 bytes sem decodificação (0,27 % — dados dentro de `.text` e
enchimento). Distribuição: `mov` 31 %, `call` 7,3 %, `lea` 6,3 %, `je` 4,7 %, `test` 4,5 %,
`cmp` 3,6 %, `movaps` 3,5 %; SSE é onipresente (`movss` 198 k, `mulps` 148 k, `addps` 101 k,
`shufps` 35 k). `x87` praticamente não aparece; **AVX/VEX e REX com `r8..r15` aparecem
normalmente** (o censo lista `r14` com 182 k usos).

### 7.2 O que precisa ser reescrito, não estendido

1. **Lifter 32 → 64 bits.** Não é um `if`: muda o decodificador (REX, `r8..r15`,
   RIP-relativo, imediato de 64 bits, `movabs`), o contexto (`rax..r15`, 16 XMM), a aritmética
   (largura 64, `movsxd`, shifts mascarados por 63), e o conjunto de instruções (193 → 663
   mnemônicas; capstone lista AVX/VEX na amostra). O lifter atual **não compila** para uma
   entrada PE32+.
2. **Modelo de memória.** O base usa “4 GB planos + deslocamento”. Para 64 bits a solução mais
   barata e mais fiel é **identidade**: mapear a imagem em `0x140000000` de verdade
   (`mmap MAP_FIXED_NOREPLACE`) e deixar ponteiros de convidado serem ponteiros reais. Isso
   funciona no arm64 Android (VA de 39 bits cobre 0x140000000 com folga), mas muda o
   contrato de todo o código gerado e do teste diferencial.
3. **SEH x64.** O esquema de `fs:[0]` + funclets não existe em x64. É preciso implementar
   *virtual unwinding* sobre `.pdata`/`UNWIND_INFO` (186 mil funções) e o `__CxxFrameHandler4`
   do MSVC, incluindo `__try/__except`, `__finally` e C++ com `catch` por tipo. É o maior
   item isolado do port — maior que o lifter.
4. **Modelo de ordenação.** x86-64 é TSO; ARM64 é fracamente ordenado. Toda operação atômica
   e todo `lock` precisa de `acquire`/`release` explícitos (ou fences completas). O base já
   faz isso para `lock` em 32 bits, mas a superfície aqui é muito maior (o RAGE usa threads
   de streaming, job system e alocadores concorrentes).
5. **ABI.** Chamadas do convidado para o host (HLE) passam de `__fastcall`/`cdecl` de 32 bits
   para **Win64** (RCX/RDX/R8/R9, sombra de 32 bytes, `__m128` em XMM, agregados por
   referência). Cada thunk HLE precisa de ponte/`shim`; chamadas do host para código gerado
   precisam do caminho inverso.
6. **Páginas de 16 KB.** Android 15+ pode usar página de 16 KB. O jogo pede `VirtualProtect`
   com granularidade de 4 KB. Emular proteção por página de 4 KB sobre páginas de 16 KB não é
   possível sem *emulação* (shadow mapping): a limitação precisa ser documentada e a política
   (arredondar para 16 KB e manter W^X frouxo) decidida.
7. **Escala.** 12,4 M de instruções medidas (provavelmente ~17 M com a segunda `.text`)
   contra 5,73 M do base. Pela taxa do base (640 MB de C para 5,73 M de instruções, ~112 B por
   instrução), o C gerado fica em **1,4–2,5 GB**; o `.so` final, **500–900 MB**. Compilar isso
   em 4 vCPU (runner público) é viável mas apertado: ~0,135 core-min por MB de C no base →
   **~4,5 core-horas** → ~70 min em 4 núcleos, mais link (um `.so` com ~190 mil funções; o
   linker precisa de vários GB de RAM). O limite de 6 h por job do GitHub é suficiente, mas
   sem margem para erro; o plano é dividir o codegen em vários `.so` por subsistema.

### 7.3 A segunda `.text` (21,8 MB) — o achado que muda o plano

O executável tem **duas** seções `Execute/Read/Write` chamadas `.text`. A segunda
(`0x145F66000`, 21,8 MB) **não está coberta por `.pdata`** e o entry point salta para dentro
dela nos primeiros bytes:

```
142e133d0: sub  rsp, 0x58
142e133d4: call 0x142e13af8
142e133d9: add  rsp, 0x28
142e133dd: jmp  0x142e1325c
...
142e13451: jmp  0x146c96c7b      <- dentro da segunda .text
142e13456: xchg qword ptr [rsp], rbp
142e1345a: jmp  0x146591054      <- dentro da segunda .text
```

E há prefixos `bnd` (`bnd jae`, `bnd ret`) e sondagem manual de pilha com `cmovb` — padrão de
código ofuscado/protegido (Arxan/Denuvo), não de compilador. A entropia confirma o quadro:

| Seção | Original | Crack |
|---|---|---|
| `.text` (1ª) | **8,00** (criptografada) | **6,68** (código legível) |
| `.text` (2ª) | 7,93 | 7,44 |

Conclusão com evidência: **o `Crack/RDR2.exe` é um dump do original já descriptografado** —
mesma `ImageBase`, mesmas VAs, mesmo tamanho de `.pdata`, mesma `.reloc`, mas com o diretório
de relocações zerado no cabeçalho (o cracker fixou a base). A primeira `.text` é liftável; a
segunda não é, sem antes descobrir o que é.

Isso é um **bloqueio declarado**: 21,8 MB de código executável sem tabela de unwind, com
assinatura de ofuscador, alcançados a partir do entry point. Não dá para levantar por
varredura estática com confiança. O caminho é instrumentar (trace de execução no Windows, ou
`perf`/Intel PT) para descobrir quais blocos dessa seção realmente rodam depois que o DRM já
foi neutralizado pelo crack, e substituí-los por stubs/implementação própria — mas isso é
trabalho separado e precisa ser medido antes de prometer qualquer coisa.

### 7.4 Launcher, Social Club e online

Strings reais do executável: `\\\\.\\pipe\\RDR2Launcher_Pipe`, `Launcher.exe`,
`socialclub.dll`, `%s.scauth.rockstargames.com`, `*.rockstargames.com`,
`VK_LAYER_ROCKSTAR_GAMES_social_club`. O jogo espera o launcher da Rockstar por named pipe e
o Social Club por DLL. O crack já substitui esses dois (`Crack/socialclub.dll`,
`Crack/launc.dll`, `Crack/Launcher.exe`). Para o port, o modo offline tem que ser explícito:
stubs que respondem o handshake mínimo, logados, e nenhuma tentativa de rede.

### 7.5 Gráficos: o RDR2 tem Vulkan nativo — e isso não basta

Confirmado por strings: `API: VULKAN`, `Attempting to Create Adapter Vulkan`,
`kSettingAPI_Vulkan`, `vulkan-1.dll` via `LoadLibrary`, `VK_LAYER_ROCKSTAR_GAMES_social_club`.
Ou seja: **não precisamos de DXVK-native para o caminho Vulkan**, ao contrário do base. Mas
há dois problemas grandes, tratados em `docs/VULKAN_CAPS.md`:

- **Texturas BC.** O conteúdo do PC é BC1/BC3/BC4/BC5/BC7 (`.ytd` dentro dos `.rpf`). Adreno
  e Mali **não expõem** `VK_FORMAT_BC*` no Vulkan. Sem transcode BC→ASTC/ETC2 (offline, de
  dezenas de GB) ou uma camada que decodifique BC na CPU/GPU, o jogo não tem textura.
- **Superfície.** `VK_KHR_win32_surface` tem que virar `VK_KHR_android_surface` com
  `ANativeWindow`, e o jogo precisa ser convencido de que não há `VK_EXT_full_screen_exclusive`
  nem `VK_KHR_win32_surface` disponível — normalmente por um `vkGetInstanceProcAddr` que
  filtra extensões e devolve a lista androide.

---

## Decisão sobre o insumo

Hipótese do pedido: usar os executáveis de `crack/` porque os comerciais vêm empacotados.
**Confirmada, com os números acima**: o `RDR2.exe` original tem `.text` com entropia 8,00
(criptografado, 50,5 MB de ruído); o do `Crack/` tem 6,68 e desmonta em código coerente,
com o mesmo entry point (`0x142E133D0`), a mesma `.pdata` e os mesmos imports. O que falta no
crack é a tabela `.reloc` (removida do diretório) — e ela existe, íntegra, no original.

Decisão: **analisar com os dois**. `.reloc`, `.pdata` e Load Config vêm do original (são
metadados, não código); o `.text` legível vem do crack. Os SHA-256 dos dois estão no
manifesto do repositório privado `rdr2-codegen`. Nenhum dos dois é copiado para repositório
público nem para o CI.

O que **não** serve, e por quê: a segunda `.text` de 21,8 MB (sem `.pdata`, ofuscada) e
tudo que depende do launcher/Social Club. Ver §7.3 e §7.4.
