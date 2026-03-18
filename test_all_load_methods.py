import subprocess
import os
import sys

def test_load_method(method_name):
    """测试单个加载方式"""
    print(f"正在测试: {method_name}")
    
    # 创建测试配置
    config = {
        "shellcode_path": "beacon.bin",
        "arch": "x64",
        "load_method": method_name,
        "enable_debug": True
    }
    
    # 生成C代码（通过调用loader.py生成）
    # 由于FastMCP模块不能直接导入，我们使用测试脚本的方式
    
    # 创建临时测试脚本
    test_script = f'''# -*- coding: utf-8 -*-
import sys
import os
sys.path.insert(0, 'e:\\\\peixun\\\\MCP\\\\loaderMCP')
os.chdir('e:\\\\peixun\\\\MCP\\\\loaderMCP')

from loader import generate_full_loader

# 生成代码
code = generate_full_loader(
    shellcode_path="beacon.bin",
    arch="x64",
    load_method="{method_name}",
    enable_debug=True
)

# 保存到文件
with open("test_loader_{method_name.replace(' ', '_').replace('-', '_')}.c", "w", encoding='utf-8') as f:
    f.write(code)

print("SUCCESS")
'''
    
    # 写入临时脚本
    temp_script_path = f"temp_test_{method_name.replace(' ', '_').replace('-', '_')}.py"
    with open(temp_script_path, "w", encoding='utf-8') as f:
        f.write(test_script)
    
    # 运行测试脚本
    try:
        result = subprocess.run(
            ["python3", temp_script_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0 or "SUCCESS" not in result.stdout:
            print(f"  ❌ 生成失败")
            if result.stderr:
                print(f"  错误: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ❌ 生成异常: {e}")
        return False
    
    # 编译生成的C代码
    c_file_path = f"test_loader_{method_name.replace(' ', '_').replace('-', '_')}.c"
    exe_file_path = f"test_loader_{method_name.replace(' ', '_').replace('-', '_')}.exe"
    
    try:
        result = subprocess.run(
            ["gcc", c_file_path, "-o", exe_file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"  ❌ 编译失败")
            print(f"  错误: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ❌ 编译异常: {e}")
        return False
    
    print(f"  ✅ 成功")
    
    # 清理临时文件
    try:
        os.remove(temp_script_path)
        os.remove(c_file_path)
        os.remove(exe_file_path)
    except:
        pass
    
    return True

def main():
    """测试所有14种加载方式"""
    
    # x64支持的14种加载方式
    load_methods = [
        "CreateThreadpoolWait Load",
        "Fiber Load",
        "NtTestAlert Load",
        "SEH Except Load",
        "TLS CallBack Load",
        "Dynamic Load",
        "Dynamic Load plus",
        "Syscall Load",
        "APC-Inject Load",
        "Early Brid APC-Inject Load",
        "NtCreateSection-Inject Load",
        "OEP Hiijack-Inject Load",
        "Thread Hiijack-Inject Load",
        "Module Stomp"
    ]
    
    print("=" * 60)
    print("测试所有14种加载方式")
    print("=" * 60)
    print()
    
    success_count = 0
    fail_count = 0
    failed_methods = []
    
    for method in load_methods:
        if test_load_method(method):
            success_count += 1
        else:
            fail_count += 1
            failed_methods.append(method)
        print()
    
    print("=" * 60)
    print(f"测试完成: {success_count} 成功, {fail_count} 失败")
    print("=" * 60)
    
    if failed_methods:
        print()
        print("失败的加载方式:")
        for method in failed_methods:
            print(f"  - {method}")
    
    return fail_count == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
