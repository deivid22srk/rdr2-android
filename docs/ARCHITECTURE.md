# Arquitetura do port

Este documento descreve como o RDR2 é transformado em um APK arm64 e onde cada peça roda.
Ele parte do que o RunnerRecompiled já resolve para x86 de 32 bits (ver
`docs/BASE_ANALYSIS.md`) e diz o que muda para PE32+ x86-64.

```
                      (máquina do usuário, uma vez)                (aparelho)
 ┌──────────────┐   ┌──────────────────────────┐   ┌─────────────────────────────────┐
 │ RDR2.exe     │──▶│ catalog64  → funções     │──▶│ lib/librdr2game.so              │
 │ (PE32+)      │   │ lift64     → C           │   │  código do jogo compilado p/ ARM │
 │ + .reloc do  │   │ clang NDK  → .o          │   └─────────────────────────────────┘
 │   original   │   └──────────────────────────┘                 ▲
 └──────────────┘                                                 │ dlopen / JNI
                                                                  │
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ librdr2rt.so  (runtime, escrito à mão, MIT)                                  │
 │  memória de convidado · carregador PE · IAT/HLE · TLS · threads · SEH ·      │
 │  shims kernel32/user32/... · áudio (AAudio) · input · VFS dos .rpf           │
 └──────────────────────────────────────────────────────────────────────────────┘
                                                                  ▲
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ APK (Java + JNI)                                                             │
 │  Activity de jogo · ANativeWindow · input · armazenamento · sonda Vulkan     │
 └──────────────────────────────────────────────────────────────────────────────┘
```

## 1. Modelo de endereços: identidade

O base mapeia o convidado de 32 bits num espaço plano de 4 GB e trata endereço de convidado
como deslocamento. Para 64 bits isso não é necessário e atrapalha: **o convidado roda nos
próprios endereços**.

- A imagem é mapeada em `0x140000000` com `mmap(MAP_FIXED_NOREPLACE)` — o Android usa VA de
  39 bits, então o endereço é alcançável. Se já estiver ocupado, o processo falha e loga; não
  há tentativa de “relocar” o jogo (o crack nem tem tabela `.reloc`).
- Toda alocação do convidado (`VirtualAlloc`) é um `mmap` real; o ponteiro devolvido é o
  ponteiro que o código gerado usa.
- Consequência: nenhuma tradução de ponteiro, nenhum offset, nenhum `MEM_BASE`. O lifter
  emite `*(uint64_t*)(uintptr_t)addr` e pronto. É o que `runtime/x64rt.h` faz.
- Consequência ruim: um ponteiro inválido do jogo é um SIGSEGV no host. O runtime instala
  handler e traduz o PC do host para o endereço de convidado antes de logar (o base já faz
  isso em `rt_host_android.c`).

**Páginas de 16 KB.** Android 15+ pode ter página de 16 KB. `VirtualProtect` do jogo pede
granularidade de 4 KB; `mprotect` só muda página inteira. Política inicial: arredondar a
proteção para 16 KB e manter as páginas de código como `R|X` e os dados como `R|W`, aceitando
que dois “pedaços” de 4 KB com proteções diferentes na mesma página de 16 KB compartilhem a
proteção mais permissiva. Isso é uma **limitação conhecida**, documentada e logada quando
ocorre — não uma emulação fiel.

## 2. Código gerado

- **Unidade de tradução**: uma função = uma função C `void f_<endereço>(X64Ctx *c)`.
- **Partição**: shards de ~2–3 GB no total divididos em arquivos de ~3 MB; cada shard declara
  só as funções que chama (`lifted.h` por shard), para o compilador não carregar um header de
  190 mil protótipos.
- **Tabela de despacho**: um array ordenado `{endereço, função}` por módulo, para chamadas
  indiretas e para `call` cujo alvo não é direto. Alvo não encontrado = **trap explícita**
  com o endereço no log (nunca “retorna 0 e segue”).
- **Flags**: materializadas a cada instrução que as altera (`X64Flags`), em vez do esquema
  preguiçoso do base. Mais lento, muito mais fácil de validar — e o teste diferencial
  compara flags bit a bit. Se o perfil mostrar custo, migra-se para preguiçoso depois.
- **Registradores**: em `ctx->r[i]`, sem cache em locais C na primeira versão. O compilador
  consegue manter os quentes em registradores de verdade quando o bloco básico é grande;
  medir antes de otimizar.

## 3. Chamadas entre convidado e host (ABI)

- Convidado → convidado: direto, `f_x(c)`, com o endereço de retorno empilhado **na pilha do
  convidado** (é o que o código x86 espera; o `ret` do callee o consome).
- Convidado → HLE: a IAT aponta para um **thunk** gerado por script a partir do nome e da
  assinatura: copia RCX/RDX/R8/R9 + `[rsp+0x28...]` (sombra de 32 bytes do Win64) para os
  argumentos da função C do runtime, chama, devolve RAX/RDX/XMM0 conforme o tipo. Nada de
  `libffi` no caminho quente; o thunk é C compilado.
- Host → convidado (callbacks, WndProc, threads): mesma ponte, no sentido inverso; o runtime
  monta `X64Ctx`, ajusta a pilha de convidado e chama a função levantada.

A sombra de 32 bytes do Win64 é **obrigatória** e é uma diferença real em relação a AAPCS64:
todo thunk reserva `sub rsp, 0x28` antes de chamar, senão o callee sobrescreve o próprio
endereço de retorno.

## 4. Exceções (o maior item)

x64 não usa `fs:[0]`; usa `.pdata`/`UNWIND_INFO` com *unwind codes*. Plano:

1. **Virtual unwinding**: dado `(RIP, RSP)`, achar o `RUNTIME_FUNCTION`, aplicar os unwind
   codes para recuperar RSP/RBP/registros salvos do frame anterior, e repetir. Base para
   stack traces e para qualquer `RtlUnwind`.
2. **SEH**: `__try/__except/__finally` compilados pelo MSVC registram escopos na pilha
   (`SCOPETABLE`); o dispatcher precisa chamar o filtro, decidir e retomar o frame — o
   equivalente do `x86_resume_*` do base, mas guiado por tabela.
3. **C++ EH**: `__CxxFrameHandler3/4` com `FuncInfo`, `TryBlockMap`, `HandlerType`, e
   desmontagem de objetos (`__CxxUnwind`). O runtime precisa implementar o contrato
   `RtlVirtualUnwind` + `RtlUnwindEx` que o handler do MSVC espera.
4. Só depois disso o CRT da Microsoft (msvcr140/msvcp140 do VC++ 2015-2022) pode ser
   levantado com o mesmo lifter, como o base fez com o VC80 — é o caminho que faz
   `std::string`, locale e exceções funcionarem iguais.

Até o passo 4 existir, o plano B é HLE de CRT, que é mais trabalho e mais frágil. A ordem é
deliberada: exceções primeiro, CRT depois.

## 5. Threads, TLS e sincronização

- `CreateThread` → `pthread_create` com TEB própria, pilha de convidado própria e TLS
  (1.088 slots) no formato Windows.
- `CRITICAL_SECTION`/SRW/eventos/mutexes/semáforos → futex/pthread, com semântica de
  `WaitForSingleObject` (incluindo timeout e `WAIT_ABANDONED`).
- `lock` prefix e atômicos → `__atomic_*` com `memory_order_seq_cst`; fences completas onde
  o x86 era TSO. Isso é correto e mais lento; medir depois.
- Fibers: `ucontext` no Android (o base já usa para o handler de sinal).

## 6. Camada de dados (`.rpf`)

O jogo não abre arquivos comuns: ele lê os `.rpf` (containers proprietários) por
`CreateFile`/`ReadFile` com offsets. O runtime só precisa entregar **leituras de bytes** de
um arquivo grande — não precisa entender o formato. O caminho:

- `$RDR2_DATA` (pasta no armazenamento do aparelho) é o “drive” do jogo; caminhos
  `C:\...` do convidado são mapeados para lá.
- `CreateFile`/`ReadFile`/`SetFilePointerEx`/`GetFileSizeEx` sobre arquivos de vários GB, com
  `pread`, sem carregar tudo na memória.
- Nada de `.rpf` no APK e nada de `.rpf` no CI.

## 7. Áudio, input, janela

- Áudio: o RDR2 importa `DSOUND.dll`, `WINMM.dll`, `MF.dll`, `MFPlat.dll`,
  `MFReadWrite.dll` — não XAudio2. O plano é HLE de DirectSound (buffers + thread de mix) e
  WASAPI-like por cima de **AAudio**; `MF*` só para vídeo Bink/MP4, que pode ficar em HLE.
- Input: `XINPUT9_1_0.dll` (#2/#3) e `DINPUT8.dll` → gamepad Android + overlay de toque, no
  mesmo desenho do base (`InputState`/`TouchPad`).
- Janela: `USER32` (CreateWindowExW, PeekMessage, SetWindowLongPtr, cursor) +
  `ANativeWindow`; mensagens sintetizadas pelo runtime, como no base.

## 8. O que é HLE e o que é levantado

Regra: **código do jogo e CRT da Microsoft são levantados; sistema operacional é HLE.**
Assim o comportamento do jogo (inclusive exceções e RTTI) é o original, e só a fronteira com
o SO é reimplementada. Cada função HLE registra uma linha na primeira chamada; o log é a
lista de tarefas real, não uma lista de desejos.

## 9. Build

- `tools/whole64.py --analyze` mede cobertura; `--emit` escreve o C.
- Compilação em paralelo com `-O1` (o `-O2` do base em 12 M de instruções estoura o tempo de
  CI), cache de objeto por hash de fonte+flags, e os arquivos maiores primeiro.
- Um `.so` por subsistema (código do jogo, CRT, runtime) para o linker não precisar de 8 GB
  de RAM de uma vez.
- O APK shell é construído sem `gen/`; o full baixa `codegen.tar.zst` da release privada.
