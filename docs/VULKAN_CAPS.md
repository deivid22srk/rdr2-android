# Vulkan: o que o jogo exige × o que o Android oferece

Estado: **documento de requisitos, ainda sem medição em aparelho.** As colunas “Android” só
podem ser preenchidas com a sonda do APK shell (`MainActivity` → “Sondar Vulkan” →
`vulkan_caps.json`). O que está marcado *(não medido)* é hipótese, não fato.

## 1. O caminho Vulkan do jogo existe e é nativo

Strings do próprio `RDR2.exe` (extraídas do binário local):

```
API: VULKAN
Attempting to Create Adapter Vulkan
Successfully Created Adapter Vulkan
kSettingAPI_Vulkan
sga_vulkan
?vulkan-1.dll
Unable to call vkEnumerateInstanceVersion for version old Vulkan runtime installed
Cannot find a compatible Vulkan installable client driver (ICD).
Do you have a compatible Vulkan installable client driver (ICD) installed?
VK_LAYER_ROCKSTAR_GAMES_social_club
```

Ou seja: `vulkan-1.dll` é carregado por `LoadLibrary` + `GetProcAddress` (não está na IAT), o
jogo escolhe o backend por configuração (`kSettingAPI_Vulkan`) e tem caminho de erro próprio
para ICD ausente. **Não é preciso DXVK-native nem VKD3D para o caminho Vulkan** — ao
contrário do projeto base, que traduz D3D9.

O `d3d12.dll` e o `dxilconv7.dll` existem no diretório, mas só entram se o jogo escolher
D3D12. O plano é forçar Vulkan e nunca oferecer DXGI/D3D12.

## 2. O que precisa ser trocado no caminho de plataforma

| Item | Windows | Android | Como |
|---|---|---|---|
| Superfície | `VK_KHR_win32_surface` + `HWND` | `VK_KHR_android_surface` + `ANativeWindow` | `vkCreateAndroidSurfaceKHR` no shim; `ANativeWindow` vem do `SurfaceView`/`GameActivity` |
| `vkGetInstanceProcAddr` | devolve tudo do driver | precisa **esconder** `VK_KHR_win32_surface`, `VK_EXT_full_screen_exclusive`, `VK_KHR_display` | filtro no shim: a lista de extensões que o jogo vê é a do Android, menos as proibidas |
| Swapchain | `VK_KHR_swapchain`, `preTransform` | rotação: `currentTransform` do Android | tratar `PRE_ROTATE`/`IDENTITY`, `compositeAlpha=INHERIT` |
| WSI | `VK_KHR_win32_surface` | `minImageCount` costuma ser 3 | pedir 3, aceitar o que vier |
| Present mode | IMMEDIATE/MAILBOX | MAILBOX nem sempre; FIFO sempre | preferir MAILBOX, cair para FIFO |
| `VK_EXT_full_screen_exclusive` | usado | não existe | recusar a extensão; o jogo já tem fallback (janela) |
| Pipeline cache | arquivo em `%LOCALAPPDATA%` | diretório do app | mapear o caminho |

## 3. Recursos que o jogo usa (a confirmar no primeiro `vkCreateDevice` logado)

O device é criado com `VkPhysicalDeviceFeatures` copiado do que o jogo consulta. Os que
importam e o motivo:

| Recurso | Por que o RDR2 precisa | Android (esperado) |
|---|---|---|
| `geometryShader` | sim, o RAGE usa | Adreno/Mali: sim |
| `tessellationShader` | terreno e personagens | sim |
| `fillModeNonSolid` | debug/wireframe | Adreno: sim; Mali: sim na maioria |
| `samplerAnisotropy` | filtro de terreno | sim |
| `depthClamp` | sombras | sim |
| `independentBlend` | MRT | sim |
| `multiDrawIndirect`, `drawIndirectFirstInstance` | renderer em lote | Vulkan 1.1: sim |
| `shaderStorageImageWriteWithoutFormat` | pós-processamento | sim |
| `textureCompressionBC` | **texturas do PC** | **Adreno e Mali: NÃO** (ver §4) |
| `textureCompressionASTC_LDR` | não usado no PC | sim (irrelevante sem transcode) |
| `shaderFloat64` | improvável | opcional, consultar |
| `sparseBinding` | improvável | consultar |
| Vulkan 1.1 (`vkEnumerateInstanceVersion`) | o jogo checa | Android 10+ com driver atual: sim |

Limites a comparar com o que a sonda devolve: `maxMemoryAllocationCount` (Adreno 4096),
`maxStorageBufferRange` (Adreno 1–2 GB), `maxPerStageDescriptorStorageBuffers`,
`maxComputeWorkGroupInvocations`, `maxFramebufferWidth/Height`, tamanho dos heaps.

## 4. O problema real: texturas BC

O conteúdo do PC é comprimido em BC (BC1/BC3/BC4/BC5/BC7) dentro dos `.ytd` nos `.rpf`.
Nenhuma GPU Android de celular expõe `VK_FORMAT_BC*` — nem Adreno, nem Mali. As saídas são:

1. **Transcode offline BC → ASTC/ETC2** (recomendado). Um passe sobre os `.rpf` na máquina do
   usuário, durante o build, gerando um segundo conjunto de dados. Custo: dezenas de GB de
   leitura/escrita, perda de qualidade (ASTC 4×4/6×6 é próximo; ETC2 é pior), e tempo de
   build de horas. Vantagem: zero custo em runtime.
2. **Decodificar BC em runtime** numa camada que intercepta `vkCmdCopyBufferToImage` /
   amostragem. Caro em CPU e memória; inviável para 20+ GB de textura.
3. **Híbrido**: transcodificar só o que o jogo carrega na primeira hora (streaming), com
   cache no aparelho. É o que faz sentido se o espaço no tablet for o limite.

Nada disso está implementado. **Este é o maior risco técnico depois do SEH**, e o único que
não depende de código do jogo: é um problema de pipeline de assets.

Medir antes de decidir: extrair um `.ytd` e contar formatos. Sem isso, qualquer estimativa de
tamanho é chute.

## 5. Como medir (procedimento)

1. Instalar o APK shell (`rdr2-android-shell`) num aparelho arm64 com Vulkan.
2. Abrir, tocar em **“Sondar Vulkan e salvar relatório”**.
3. `adb pull /sdcard/Android/data/com.deivid22srk.rdr2/files/vulkan_caps.json`.
4. Preencher a tabela §3 com os valores reais e anexar o JSON ao repositório privado
   (o JSON contém o nome do driver, não conteúdo do jogo — pode ir para `docs/` se o dono
   preferir).

O que a sonda já devolve: versão de instância, extensões de instância e de device, nome e
versão do driver, tipo de device, `VkPhysicalDeviceFeatures` relevantes, limites principais e
heaps de memória.

## 6. Conclusão provisória

O caminho Vulkan nativo é o certo e evita DXVK. O que impede o “primeiro frame” hoje não é
Vulkan: é não haver runtime nem código levantado. Quando houver, os dois pontos a atacar são
(a) a troca de superfície no shim e (b) as texturas BC.
