"""
简单测试：生成基本配置的C代码
"""
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from loader import generate_full_loader

# 测试基本配置
print("测试基本配置生成...")
result = generate_full_loader(
    shellcode_path="test.bin",
    arch="x64",
    load_method="Dynamic Load",
    enable_debug=False
)

if "错误" in result:
    print(f"生成失败: {result}")
else:
    print(f"生成成功！代码长度: {len(result)} 字符")
    # 保存到文件
    with open("simple_test.c", "w", encoding="utf-8") as f:
        f.write(result)
    print("已保存到 simple_test.c")
