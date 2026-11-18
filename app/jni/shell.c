/*
 * Shell JNI: no game code.
 *
 * It answers two questions that the port needs before any game code exists:
 *   1. what the device's Vulkan driver actually offers (docs/VULKAN_CAPS.md is
 *      filled from this output on real hardware), and
 *   2. what this build is (variant, ABI, page size), so a log says which APK
 *      produced it.
 *
 * Everything here is read-only probing: no allocation of game-sized memory, no
 * swapchain, no surface. The result is a JSON string the Java side shows and
 * writes to the app's files directory.
 */
#include <jni.h>
#include <android/log.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

#define TAG "rdr2shell"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ---- tiny growable string ------------------------------------------------ */
typedef struct {
    char *p;
    size_t len, cap;
} sb;

static void sb_init(sb *b) { b->cap = 4096; b->len = 0; b->p = malloc(b->cap); b->p[0] = 0; }

static void sb_printf(sb *b, const char *fmt, ...)
{
    va_list ap;
    for (;;) {
        va_start(ap, fmt);
        int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
        va_end(ap);
        if (n < 0) return;
        if ((size_t)n < b->cap - b->len) { b->len += (size_t)n; return; }
        size_t ncap = b->cap * 2 + (size_t)n;
        char *np = realloc(b->p, ncap);
        if (!np) return;
        b->p = np;
        b->cap = ncap;
    }
}

static const char *vkres(VkResult r)
{
    switch (r) {
    case VK_SUCCESS: return "VK_SUCCESS";
    case VK_NOT_READY: return "VK_NOT_READY";
    case VK_TIMEOUT: return "VK_TIMEOUT";
    case VK_INCOMPLETE: return "VK_INCOMPLETE";
    case VK_ERROR_OUT_OF_HOST_MEMORY: return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY: return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_INITIALIZATION_FAILED: return "VK_ERROR_INITIALIZATION_FAILED";
    case VK_ERROR_LAYER_NOT_PRESENT: return "VK_ERROR_LAYER_NOT_PRESENT";
    case VK_ERROR_EXTENSION_NOT_PRESENT: return "VK_ERROR_EXTENSION_NOT_PRESENT";
    case VK_ERROR_INCOMPATIBLE_DRIVER: return "VK_ERROR_INCOMPATIBLE_DRIVER";
    case VK_ERROR_FORMAT_NOT_SUPPORTED: return "VK_ERROR_FORMAT_NOT_SUPPORTED";
    default: return "VK_ERROR_OTHER";
    }
}

#define BOOLF(f) ((f) ? "true" : "false")

/* ---- build info ---------------------------------------------------------- */
JNIEXPORT jstring JNICALL
Java_com_deivid22srk_rdr2_MainActivity_nativeBuildInfo(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    sb b; sb_init(&b);
    long page = sysconf(_SC_PAGESIZE);
    sb_printf(&b, "{\"variant\":\"%s\",\"abi\":\"%s\",\"page_size\":%ld}\n",
#ifdef RDR2_FULL_BUILD
              "full", "arm64-v8a", page
#else
              "shell", "arm64-v8a", page
#endif
    );
    jstring out = (*env)->NewStringUTF(env, b.p);
    free(b.p);
    return out;
}

/* ---- Vulkan probe -------------------------------------------------------- */
JNIEXPORT jstring JNICALL
Java_com_deivid22srk_rdr2_MainActivity_nativeVulkanProbe(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    sb b; sb_init(&b);
    sb_printf(&b, "{\n");

    uint32_t instVer = 0;
    PFN_vkEnumerateInstanceVersion enumVer =
        (PFN_vkEnumerateInstanceVersion)vkGetInstanceProcAddr(NULL, "vkEnumerateInstanceVersion");
    VkResult r = enumVer ? enumVer(&instVer) : VK_SUCCESS;
    if (!enumVer) instVer = VK_API_VERSION_1_0;
    sb_printf(&b, "  \"instance_version\": \"%u.%u.%u\",\n",
              VK_API_VERSION_MAJOR(instVer), VK_API_VERSION_MINOR(instVer), VK_API_VERSION_PATCH(instVer));
    sb_printf(&b, "  \"enumerate_instance_version_result\": \"%s\",\n", vkres(r));

    /* instance extensions */
    uint32_t n = 0;
    vkEnumerateInstanceExtensionProperties(NULL, &n, NULL);
    VkExtensionProperties *ext = calloc(n ? n : 1, sizeof(*ext));
    vkEnumerateInstanceExtensionProperties(NULL, &n, ext);
    sb_printf(&b, "  \"instance_extensions\": [");
    int has_android_surface = 0;
    for (uint32_t i = 0; i < n; i++) {
        sb_printf(&b, "%s\"%s\"", i ? "," : "", ext[i].extensionName);
        if (!strcmp(ext[i].extensionName, "VK_KHR_android_surface")) has_android_surface = 1;
    }
    sb_printf(&b, "],\n  \"khr_android_surface\": %s,\n", BOOLF(has_android_surface));
    free(ext);

    /* instances */
    const char *want[] = { "VK_KHR_android_surface", "VK_KHR_surface" };
    const char *use[2];
    uint32_t nuse = 0;
    for (int i = 0; i < 2; i++) {
        uint32_t m = 0;
        vkEnumerateInstanceExtensionProperties(NULL, &m, NULL);
        VkExtensionProperties *e2 = calloc(m ? m : 1, sizeof(*e2));
        vkEnumerateInstanceExtensionProperties(NULL, &m, e2);
        for (uint32_t k = 0; k < m; k++)
            if (!strcmp(e2[k].extensionName, want[i])) use[nuse++] = want[i];
        free(e2);
    }
    VkApplicationInfo ai = { .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
                             .pApplicationName = "rdr2-caps", .apiVersion = VK_API_VERSION_1_1 };
    VkInstanceCreateInfo ci = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
                               .pApplicationInfo = &ai,
                               .enabledExtensionCount = nuse, .ppEnabledExtensionNames = use };
    VkInstance inst = VK_NULL_HANDLE;
    r = vkCreateInstance(&ci, NULL, &inst);
    sb_printf(&b, "  \"create_instance\": \"%s\",\n", vkres(r));
    if (r != VK_SUCCESS) { sb_printf(&b, "  \"devices\": []\n}\n"); goto done; }

    uint32_t ndev = 0;
    r = vkEnumeratePhysicalDevices(inst, &ndev, NULL);
    sb_printf(&b, "  \"physical_device_count\": %u,\n", ndev);
    VkPhysicalDevice *devs = calloc(ndev ? ndev : 1, sizeof(*devs));
    if (ndev) vkEnumeratePhysicalDevices(inst, &ndev, devs);
    sb_printf(&b, "  \"devices\": [\n");
    for (uint32_t i = 0; i < ndev; i++) {
        VkPhysicalDeviceProperties p;
        vkGetPhysicalDeviceProperties(devs[i], &p);
        VkPhysicalDeviceFeatures f;
        vkGetPhysicalDeviceFeatures(devs[i], &f);
        VkPhysicalDeviceMemoryProperties mp;
        vkGetPhysicalDeviceMemoryProperties(devs[i], &mp);
        uint32_t next_n = 0;
        vkEnumerateDeviceExtensionProperties(devs[i], NULL, &next_n, NULL);
        VkExtensionProperties *de = calloc(next_n ? next_n : 1, sizeof(*de));
        vkEnumerateDeviceExtensionProperties(devs[i], NULL, &next_n, de);

        sb_printf(&b, "    {\n");
        sb_printf(&b, "      \"name\": \"%s\",\n", p.deviceName);
        sb_printf(&b, "      \"api_version\": \"%u.%u.%u\",\n",
                  VK_API_VERSION_MAJOR(p.apiVersion), VK_API_VERSION_MINOR(p.apiVersion),
                  VK_API_VERSION_PATCH(p.apiVersion));
        sb_printf(&b, "      \"driver_version\": %u,\n", p.driverVersion);
        sb_printf(&b, "      \"vendor_id\": %u, \"device_id\": %u, \"device_type\": %d,\n",
                  p.vendorID, p.deviceID, (int)p.deviceType);
        sb_printf(&b, "      \"limits\": {"
                      "\"maxImageDimension2D\":%u,"
                      "\"maxImageDimension3D\":%u,"
                      "\"maxImageDimensionCube\":%u,"
                      "\"maxUniformBufferRange\":%u,"
                      "\"maxStorageBufferRange\":%u,"
                      "\"maxMemoryAllocationCount\":%u,"
                      "\"maxSamplerAllocationCount\":%u,"
                      "\"maxPerStageDescriptorSamplers\":%u,"
                      "\"maxPerStageDescriptorUniformBuffers\":%u,"
                      "\"maxPerStageDescriptorStorageBuffers\":%u,"
                      "\"maxPerStageDescriptorSampledImages\":%u,"
                      "\"maxPerStageDescriptorStorageImages\":%u,"
                      "\"maxDescriptorSetSamplers\":%u,"
                      "\"maxDescriptorSetUniformBuffers\":%u,"
                      "\"maxDescriptorSetStorageBuffers\":%u,"
                      "\"maxDescriptorSetSampledImages\":%u,"
                      "\"maxDescriptorSetStorageImages\":%u,"
                      "\"maxVertexInputAttributes\":%u,"
                      "\"maxVertexInputBindings\":%u,"
                      "\"maxVertexInputAttributeOffset\":%u,"
                      "\"maxVertexInputBindingStride\":%u,"
                      "\"maxVertexOutputComponents\":%u,"
                      "\"maxFragmentInputComponents\":%u,"
                      "\"maxFragmentOutputAttachments\":%u,"
                      "\"maxComputeSharedMemorySize\":%u,"
                      "\"maxComputeWorkGroupInvocations\":%u,"
                      "\"maxComputeWorkGroupSize\":[%u,%u,%u],"
                      "\"maxViewportDimensions\":[%u,%u],"
                      "\"maxColorAttachments\":%u,"
                      "\"maxFramebufferWidth\":%u,"
                      "\"maxFramebufferHeight\":%u,"
                      "\"maxDrawIndirectCount\":%u,"
                      "\"timestampPeriod\":%f"
                      "},\n",
                  p.limits.maxImageDimension2D, p.limits.maxImageDimension3D,
                  p.limits.maxImageDimensionCube, p.limits.maxUniformBufferRange,
                  p.limits.maxStorageBufferRange, p.limits.maxMemoryAllocationCount,
                  p.limits.maxSamplerAllocationCount, p.limits.maxPerStageDescriptorSamplers,
                  p.limits.maxPerStageDescriptorUniformBuffers, p.limits.maxPerStageDescriptorStorageBuffers,
                  p.limits.maxPerStageDescriptorSampledImages, p.limits.maxPerStageDescriptorStorageImages,
                  p.limits.maxDescriptorSetSamplers, p.limits.maxDescriptorSetUniformBuffers,
                  p.limits.maxDescriptorSetStorageBuffers, p.limits.maxDescriptorSetSampledImages,
                  p.limits.maxDescriptorSetStorageImages, p.limits.maxVertexInputAttributes,
                  p.limits.maxVertexInputBindings, p.limits.maxVertexInputAttributeOffset,
                  p.limits.maxVertexInputBindingStride, p.limits.maxVertexOutputComponents,
                  p.limits.maxFragmentInputComponents, p.limits.maxFragmentOutputAttachments,
                  p.limits.maxComputeSharedMemorySize, p.limits.maxComputeWorkGroupInvocations,
                  p.limits.maxComputeWorkGroupSize[0], p.limits.maxComputeWorkGroupSize[1],
                  p.limits.maxComputeWorkGroupSize[2], p.limits.maxViewportDimensions[0],
                  p.limits.maxViewportDimensions[1], p.limits.maxColorAttachments,
                  p.limits.maxFramebufferWidth, p.limits.maxFramebufferHeight,
                  p.limits.maxDrawIndirectCount, (double)p.limits.timestampPeriod);
        sb_printf(&b, "      \"features\": {"
                      "\"geometryShader\":%s,\"tessellationShader\":%s,\"fillModeNonSolid\":%s,"
                      "\"wideLines\":%s,\"largePoints\":%s,\"samplerAnisotropy\":%s,"
                      "\"depthClamp\":%s,\"depthBiasClamp\":%s,\"independentBlend\":%s,"
                      "\"multiDrawIndirect\":%s,\"drawIndirectFirstInstance\":%s,"
                      "\"shaderStorageImageWriteWithoutFormat\":%s,"
                      "\"shaderStorageImageExtendedFormats\":%s,"
                      "\"shaderImageGatherExtended\":%s,"
                      "\"sparseBinding\":%s,\"sparseResidencyBuffer\":%s,"
                      "\"textureCompressionBC\":%s,\"textureCompressionETC2\":%s,"
                      "\"textureCompressionASTC_LDR\":%s,"
                      "\"shaderFloat64\":%s,\"shaderInt64\":%s,\"shaderInt16\":%s,"
                      "\"dualSrcBlend\":%s,\"logicOp\":%s,\"robustBufferAccess\":%s"
                      "},\n",
                  BOOLF(f.geometryShader), BOOLF(f.tessellationShader), BOOLF(f.fillModeNonSolid),
                  BOOLF(f.wideLines), BOOLF(f.largePoints), BOOLF(f.samplerAnisotropy),
                  BOOLF(f.depthClamp), BOOLF(f.depthBiasClamp), BOOLF(f.independentBlend),
                  BOOLF(f.multiDrawIndirect), BOOLF(f.drawIndirectFirstInstance),
                  BOOLF(f.shaderStorageImageWriteWithoutFormat),
                  BOOLF(f.shaderStorageImageExtendedFormats), BOOLF(f.shaderImageGatherExtended),
                  BOOLF(f.sparseBinding), BOOLF(f.sparseResidencyBuffer),
                  BOOLF(f.textureCompressionBC), BOOLF(f.textureCompressionETC2),
                  BOOLF(f.textureCompressionASTC_LDR), BOOLF(f.shaderFloat64),
                  BOOLF(f.shaderInt64), BOOLF(f.shaderInt16), BOOLF(f.dualSrcBlend),
                  BOOLF(f.logicOp), BOOLF(f.robustBufferAccess));
        sb_printf(&b, "      \"memory\": {"
                      "\"memoryTypeCount\":%u,\"memoryHeapCount\":%u,"
                      "\"heaps\":[",
                  mp.memoryTypeCount, mp.memoryHeapCount);
        for (uint32_t h = 0; h < mp.memoryHeapCount; h++) {
            const VkMemoryHeap *hp = &mp.memoryHeaps[h];
            sb_printf(&b, "%s{\"size_mb\":%llu,\"device_local\":%s}", h ? "," : "",
                      (unsigned long long)(hp->size / (1024ull * 1024ull)),
                      BOOLF(hp->flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT));
        }
        sb_printf(&b, "]},\n");
        sb_printf(&b, "      \"extensions\": [");
        int has_bc = 0, has_astc = 0, has_etc2 = 0;
        for (uint32_t k = 0; k < next_n; k++) {
            sb_printf(&b, "%s\"%s\"", k ? "," : "", de[k].extensionName);
            if (!strcmp(de[k].extensionName, "VK_EXT_texture_compression_astc_hdr")) has_astc = 1;
            if (!strcmp(de[k].extensionName, "VK_EXT_astc_decode_mode")) has_bc = 1;
            if (!strcmp(de[k].extensionName, "VK_EXT_queue_family_foreign")) has_etc2 = 1;
        }
        (void)has_bc; (void)has_astc; (void)has_etc2;
        sb_printf(&b, "]\n");
        sb_printf(&b, "    }%s\n", i + 1 < ndev ? "," : "");
        free(de);
    }
    sb_printf(&b, "  ]\n}\n");
    free(devs);
    vkDestroyInstance(inst, NULL);
done:
    LOGI("vulkan probe done (%zu bytes)", b.len);
    jstring out = (*env)->NewStringUTF(env, b.p);
    free(b.p);
    return out;
}
