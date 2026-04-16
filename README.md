# LoaderMCP 项目使用说明

## 项目简介

LoaderMCP 是一个基于 FastMCP 框架的 Shellcode 加载器生成工具，能够根据用户指定的配置生成完整的 C 语言 Shellcode 加载器代码。该工具支持多种加载方式、加密技术、反检测功能和高级注入技术。

## 环境要求

### 必需环境

1. **Python 3.13+**
   - 项目要求 Python 版本 >= 3.13
   - 需要支持 pip 包管理

2. **GCC 编译器（Windows 下使用 MinGW/TDM-GCC）**
   - 用于编译生成的 C 代码
   - 推荐使用 TDM-GCC 或 MinGW-w64
   - 确保 gcc 命令可在命令行中使用

3. **MCP 客户端（可选，用于直接调用 MCP 工具）**
   - 如：Claude Desktop、Cursor 等 MCP 客户端
   - 或通过 Python 脚本间接调用

### 可选环境

1. **Shellcode 加密工具**
   - 如需使用加密功能，需要预先加密 Shellcode 文件
   - 可使用任何支持 RC4 加密的工具

## 环境配置

### 1. 安装 Python 依赖

在项目根目录下执行：

```bash
pip install -e .
```

或手动安装依赖：

```bash
pip install "mcp[cli]>=1.20.0" "jinja2>=3.0.0"
```

### 2. 安装 GCC 编译器

#### Windows 下安装 TDM-GCC

1. 下载 TDM-GCC：https://jmeubank.github.io/tdm-gcc/download/
2. 运行安装程序，选择 "Create" 安装模式
3. 确保勾选 "Add to PATH" 选项
4. 验证安装：在命令行输入 `gcc --version`

#### Linux/Mac 下安装 GCC

```bash
# Ubuntu/Debian
sudo apt-get install gcc

# macOS
xcode-select --install
```

### 3. 验证环境

创建测试脚本验证环境：

```python
import subprocess
import sys

# 检查 Python 版本
print(f"Python 版本: {sys.version}")

# 检查 GCC 版本
try:
    result = subprocess.run(['gcc', '--version'], capture_output=True, text=True)
    print(f"GCC 版本: {result.stdout.split()[2]}")
except FileNotFoundError:
    print("错误: GCC 未安装或未添加到 PATH")

# 检查 Python 依赖
try:
    import mcp
    print(f"MCP 版本: {mcp.__version__}")
except ImportError:
    print("错误: mcp 模块未安装")

try:
    import jinja2
    print(f"Jinja2 版本: {jinja2.__version__}")
except ImportError:
    print("错误: jinja2 模块未安装")
```

## MCP 工具调用

### 方式一：通过 MCP 客户端调用

#### 1. 启动 MCP 服务器

在项目根目录下执行：

```bash
python3 loader.py
```

服务器将在 stdio 模式下运行，等待 MCP 客户端连接。

#### 2. 配置 MCP 客户端（以 Claude Desktop 为例）

在 Claude Desktop 配置文件中添加：

```json
{
  "mcpServers": {
    "loaderMCP": {
      "command": "python3",
      "args": ["e:\\xxx\\xxx\\loaderMCP\\loader.py"]
    }
  }
}
```

#### 3. 调用工具

在 Claude Desktop 中直接调用：

```
请使用 generate_full_loader 工具生成一个 Shellcode 加载器，配置如下：
- shellcode_path: "beacon.bin"
- arch: "x64"
- load_method: "Dynamic Load"
- enable_debug: true
- use_dynamic_resolve: true
```

### 方式二：通过 Python 脚本调用

由于 FastMCP 模块不能直接导入，创建间接调用脚本：

```python
import subprocess
import sys

def call_generate_loader(config):
    """通过 MCP 协议调用生成工具"""
    # 构建 MCP 请求
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "generate_full_loader",
            "arguments": config
        }
    }
    
    # 调用 loader.py
    result = subprocess.run(
        [sys.executable, "loader.py"],
        input=str(request),
        capture_output=True,
        text=True
    )
    
    return result.stdout

# 示例配置
config = {
    "shellcode_path": "beacon.bin",
    "arch": "x64",
    "load_method": "Dynamic Load",
    "enable_debug": True,
    "use_dynamic_resolve": True
}

# 调用工具
code = call_generate_loader(config)
print(code)
```

### 方式三：通过测试脚本验证

使用项目提供的测试脚本：

```bash
# 测试基本功能
python3 test_full_customization.py

# 测试用户自定义配置
python3 user_config_test.py
```

## 工具参数说明

### generate_full_loader 工具参数

| 参数名 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| shellcode_path | string | "beacon.bin" | Shellcode 文件路径 |
| encrypt_shellcode | bool | false | 是否需要解密（文件已加密） |
| encryption_key | string | null | 解密密钥（加密时必填） |
| arch | string | "x64" | 架构（x64） |
| load_method | string | "Dynamic Load" | 加载方式（见下表） |
| sacrificial_dll | string | "C:\\Windows\\System32\\combase.dll" | 牺牲DLL路径（模块踩踏用） |
| enable_debug | bool | false | 启用调试输出 |
| use_dynamic_resolve | bool | false | 动态API解析 |
| anti_debug | bool | false | 反调试检测 |
| anti_sandbox | bool | false | 反沙箱检测 |
| auto_start | bool | false | 自启动配置 |
| use_process_hollowing | bool | false | 进程空洞注入 |
| enable_unhook | bool | false | EDR/AV Unhook |
| enable_anti_detection | bool | false | 反检测初始化 |

### 支持的加载方式

#### x64 架构（14种）- 
- CreateThreadpoolWait Load - 线程池等待方式
- Fiber Load - 纤程加载方式
- NtTestAlert Load - NtTestAlert函数方式
- SEH Except Load - SEH异常方式
- TLS CallBack Load - TLS回调方式
- Dynamic Load - 经典动态加载方式
- Dynamic Load plus - 动态加载增强版
- Syscall Load - 系统调用方式
- APC-Inject Load - APC注入方式
- Early Brid APC-Inject Load - 早期桥接APC注入
- NtCreateSection-Inject Load - NtCreateSection注入
- OEP Hiijack-Inject Load - OEP劫持注入
- Thread Hiijack-Inject Load - 线程劫持方式
- Module Stomp - 模块踩踏方式

## 使用示例

### 示例 1：基本加载器

```python
# 配置
config = {
    "shellcode_path": "beacon.bin",
    "load_method": "Dynamic Load",
    "enable_debug": True
}

# 生成代码
code = call_generate_loader(config)

# 保存到文件
with open("loader.c", "w") as f:
    f.write(code)

# 编译
import os
os.system("gcc loader.c -o loader.exe")
```

### 示例 2：加密 + 动态解析 + 反检测

```python
config = {
    "shellcode_path": "encrypted_beacon.bin",
    "encrypt_shellcode": True,
    "encryption_key": "MySecretKey123",
    "arch": "x64",
    "load_method": "Module Stomp",
    "sacrificial_dll": "C:\\Windows\\System32\\bcrypt.dll",
    "enable_debug": True,
    "use_dynamic_resolve": True,
    "anti_debug": True,
    "anti_sandbox": True
}
```

### 示例 3：完整功能配置

```python
config = {
    "shellcode_path": "protected.bin",
    "encrypt_shellcode": True,
    "encryption_key": "SecureKey456",
    "arch": "x64",
    "load_method": "Process Hollowing",
    "use_process_hollowing": True,
    "enable_debug": True,
    "use_dynamic_resolve": True,
    "anti_debug": True,
    "anti_sandbox": True,
    "auto_start": True,
    "enable_unhook": True,
    "enable_anti_detection": True
}
```

## 编译生成的 C 代码

### Windows 下编译

```bash
# 编译为可执行文件
gcc loader.c -o loader.exe

# 编译为 32 位可执行文件
gcc loader.c -o loader32.exe -m32

# 编译时禁用安全检查
gcc loader.c -o loader.exe -fno-stack-protector
```

### Linux 下编译

```bash
# 编译为可执行文件
gcc loader.c -o loader

# 编译为 Windows 可执行文件（交叉编译）
x86_64-w64-mingw32-gcc loader.c -o loader.exe
```

## 项目结构

```
loaderMCP/
├── loader.py                      # MCP 服务器主文件
├── config.py                      # 配置管理模块
├── load_method_registry.py        # 加载方式注册表
├── template_renderer.py            # 模板渲染器
├── resource_enhancer.py            # 资源增强器
├── pyproject.toml                 # 项目配置文件
├── README.md                     # 项目文档（本文档）
├── test_all_load_methods.py      # 所有加载方式测试脚本
├── test_full_customization.py     # 完整功能测试脚本
├── user_config_test.py            # 用户配置测试脚本
└── templates/                     # 模板目录
    ├── base.c.j2                  # 基础模板
    └── modules/                   # 功能模块模板
        ├── rc4.c.j2               # RC4 加密模块
        ├── environment_setup.c.j2 # 环境准备模块
        ├── shellcode_io.c.j2      # Shellcode IO 模块
        ├── shellcode_execution.c.j2 # Shellcode 执行模块
        └── load_methods/          # 加载方式模板（15种）
            ├── create_threadpoolwait_load.c.j2
            ├── dynamic_load.c.j2
            ├── dynamic_load_plus.c.j2
            ├── fiber_load.c.j2
            ├── apc_inject_load.c.j2
            ├── early_brid_apc_inject_load.c.j2
            ├── thread_hijack_load.c.j2
            ├── module_stomp.c.j2
            ├── seh_except_load.c.j2
            ├── syscall_load.c.j2
            ├── nttestalert_load.c.j2
            ├── tls_callback_load.c.j2
            ├── ntcreatesection_inject_load.c.j2
            ├── oep_hijack_inject_load.c.j2
            └── process_hollowing.c.j2
```

## 核心功能

### 三步流程

1. **运行环境准备**
   - 动态 API 解析（哈希方式）
   - EDR/AV Unhook
   - 反检测初始化（反调试、反沙箱）
   - 自启动配置

2. **Shellcode 读取和写入**
   - 本地文件读取（支持加密文件）
   - 内存中解密（RC4 算法）
   - 内存分配和写入

3. **Shellcode 执行**
   - 执行前检查（反调试、反沙箱）
   - 多种加载方式执行
   - 执行后清理（内存擦除、资源释放）

### 加密流程

1. 用户预先使用外部工具加密 Shellcode
2. 生成加载器时指定加密密钥
3. 加载器读取加密文件
4. 在内存中解密为原始 Shellcode
5. 执行解密后的 Shellcode

### 反检测技术

- **反调试**：检测调试器是否存在
- **反沙箱**：检测进程数量，识别沙箱环境
- **动态解析**：使用哈希方式获取 API 地址，绕过静态分析
- **Unhook**：修改 ntdll 内存保护，解除 EDR/AV hook

## 常见问题

### Q1: MCP 服务器无法启动？

**A**: 检查以下几点：
1. Python 版本是否 >= 3.13
2. 是否安装了所有依赖：`pip install "mcp[cli]>=1.20.0" "jinja2>=3.0.0"`
3. 是否使用 `python3` 命令而不是 `python`

### Q2: 生成的 C 代码编译失败？

**A**: 检查以下几点：
1. GCC 是否正确安装并添加到 PATH
2. 是否使用正确的编译命令（Windows 下使用 TDM-GCC）
3. 检查错误信息，可能是语法错误或缺少头文件

### Q3: Shellcode 文件路径错误？

**A**:
1. 确保文件路径是绝对路径
2. Windows 路径使用双反斜杠：`C:\\Windows\\System32\\beacon.bin`
3. 文件必须存在且可读

### Q4: 加密功能不工作？

**A**:
1. 确保 encrypt_shellcode 设置为 True
2. 必须提供 encryption_key 参数
3. Shellcode 文件必须预先加密（使用 RC4 算法）

### Q5: 加载方式不支持？

**A**:

1. 检查架构参数（arch）是否正确
2. 不同架构支持的加载方式不同
3. 查看支持的加载方式列表

## 测试验证

### 运行完整测试

```bash
# 测试所有14种加载方式
python3 test_all_load_methods.py

# 测试基本功能
python3 test_full_customization.py

# 测试用户自定义配置
python3 user_config_test.py
```

### 测试结果

✅ **所有14种加载方式已通过完整测试验证**

测试覆盖：
- 代码生成：所有加载方式都能成功生成C代码
- GCC编译：所有生成的C代码都能用GCC成功编译
- 功能验证：包含所有用户自定义参数的支持

测试环境：
- Windows 10/11
- Python 3.13+
- GCC (MinGW-w64)
- x64 架构

### 手动验证

1. 生成加载器代码
2. 保存为 loader.c
3. 编译：`gcc loader.c -o loader.exe`
4. 运行：`loader.exe`
5. 检查输出和 Shellcode 执行情况

## 技术支持

如遇到问题，请检查：
1. 环境配置是否正确
2. 依赖是否完整安装
3. 参数是否正确配置
4. 生成的 C 代码是否有语法错误

## 更新日志

### v0.1.0 (当前版本) - ✅ **测试验证完成**
- ✅ 实现基于 FastMCP 的 Shellcode 加载器生成工具
- ✅ 支持 14 种加载方式（x64）/ 15 种加载方式（x86），全部测试通过
- ✅ 支持加密、动态解析、反检测等功能
- ✅ 支持进程空洞注入、模块踩踏等高级技术
- ✅ 完整的三步流程：环境准备 → Shellcode IO → 执行
- ✅ 13 个用户自定义参数全面支持
- ✅ 所有加载方式 GCC 编译验证通过
- ✅ 新增 7 种加载方式模板文件

#### 测试状态
- ✅ CreateThreadpoolWait Load - 测试通过
- ✅ Fiber Load - 测试通过
- ✅ NtTestAlert Load - 测试通过
- ✅ SEH Except Load - 测试通过
- ✅ TLS CallBack Load - 测试通过
- ✅ Dynamic Load - 测试通过
- ✅ Dynamic Load plus - 测试通过
- ✅ Syscall Load - 测试通过
- ✅ APC-Inject Load - 测试通过
- ✅ Early Brid APC-Inject Load - 测试通过
- ✅ NtCreateSection-Inject Load - 测试通过
- ✅ OEP Hiijack-Inject Load - 测试通过
- ✅ Thread Hiijack-Inject Load - 测试通过
- ✅ Module Stomp - 测试通过

## 项目特点

1. **完整测试验证**：所有14种加载方式都经过代码生成和GCC编译验证
2. **灵活配置**：支持13个用户自定义参数，满足不同使用场景
3. **模块化设计**：清晰的模板架构，易于维护和扩展
4. **多种技术**：涵盖主流Shellcode加载技术和反检测方法
5. **MCP集成**：完美集成FastMCP框架，支持多种调用方式
