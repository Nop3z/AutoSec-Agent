"""
从提取的固件文件生成 export-for-ai 目录结构。
用于在没有 Ghidra 的情况下进行基本的漏洞扫描。
"""

import os
import subprocess
from pathlib import Path

from core.path_guard import get_project_dir


def generate_export_for_ai(project_name: str) -> dict:
    """
    从 extractions/ 目录提取二进制文件信息，生成 export-for-ai/ 结构。
    
    对于每个二进制文件，生成：
    - strings.txt: 字符串提取
    - imports.txt: 导入函数（通过 nm/strings 猜测）
    - exports.txt: 导出符号
    - decompile/placeholder.txt: 占位符（提示没有反编译）
    
    Returns:
        {"success": bool, "message": str, "binaries": list}
    """
    project_dir = get_project_dir(project_name)
    extractions_dir = os.path.join(project_dir, "extractions")
    export_base = os.path.join(project_dir, "export-for-ai")
    
    if not os.path.exists(extractions_dir):
        return {
            "success": False,
            "message": f"未找到提取目录: {extractions_dir}",
            "binaries": []
        }
    
    os.makedirs(export_base, exist_ok=True)
    
    # 查找所有二进制文件
    binary_files = []
    for root, dirs, files in os.walk(extractions_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            # 跳过目录和明显不是二进制的文件
            if os.path.islink(filepath):
                continue
            
            # 使用 file 命令检查文件类型
            try:
                result = subprocess.run(
                    ["file", "-b", filepath],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                file_type = result.stdout.lower()
                
                # 识别 ELF 二进制文件
                if "elf" in file_type and ("executable" in file_type or "shared object" in file_type):
                    binary_files.append(filepath)
            except:
                pass
    
    if not binary_files:
        return {
            "success": False,
            "message": "未找到 ELF 二进制文件",
            "binaries": []
        }
    
    processed = []
    for binary_path in binary_files:
        # 使用相对路径作为二进制名称（清理特殊字符）
        rel_path = os.path.relpath(binary_path, extractions_dir)
        binary_name = rel_path.replace("/", "_").replace("\\", "_").replace(".", "_")
        
        binary_export_dir = os.path.join(export_base, binary_name)
        os.makedirs(binary_export_dir, exist_ok=True)
        os.makedirs(os.path.join(binary_export_dir, "decompile"), exist_ok=True)
        
        # 1. 提取字符串
        strings_path = os.path.join(binary_export_dir, "strings.txt")
        try:
            with open(strings_path, "w", encoding="utf-8", errors="ignore") as out:
                # 使用 strings 命令
                result = subprocess.run(
                    ["strings", "-n", "4", binary_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                out.write(result.stdout)
        except Exception as e:
            with open(strings_path, "w") as out:
                out.write(f"# Error extracting strings: {e}\n")
        
        # 2. 尝试获取导入/导出符号
        imports_path = os.path.join(binary_export_dir, "imports.txt")
        exports_path = os.path.join(binary_export_dir, "exports.txt")
        
        try:
            # 使用 nm 获取符号
            result = subprocess.run(
                ["nm", "-D", binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            imports = []
            exports = []
            
            for line in result.stdout.split("\n"):
                if " U " in line:  # Undefined = 导入
                    imports.append(line)
                elif any(c in line for c in "T W V D B"):  # 定义的符号 = 导出
                    exports.append(line)
            
            with open(imports_path, "w") as f:
                f.write("\n".join(imports) if imports else "# No dynamic imports found\n")
            
            with open(exports_path, "w") as f:
                f.write("\n".join(exports) if exports else "# No exports found\n")
                
        except Exception as e:
            with open(imports_path, "w") as f:
                f.write(f"# Error: {e}\n")
            with open(exports_path, "w") as f:
                f.write(f"# Error: {e}\n")
        
        # 3. 创建反编译占位符
        placeholder_path = os.path.join(binary_export_dir, "decompile", "placeholder.txt")
        with open(placeholder_path, "w") as f:
            f.write(f"# No decompiled code available for {rel_path}\n")
            f.write("# This is a placeholder. Use Ghidra/Radare2 for full decompilation.\n")
            f.write(f"# Original binary: {binary_path}\n")
            f.write(f"# File type: {file_type}\n")
        
        processed.append({
            "name": binary_name,
            "original_path": rel_path,
            "export_dir": binary_export_dir
        })
    
    return {
        "success": True,
        "message": f"成功处理 {len(processed)} 个二进制文件",
        "binaries": processed
    }
