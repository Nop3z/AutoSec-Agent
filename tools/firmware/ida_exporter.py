import os
import subprocess

from langchain.tools import tool

from core.path_guard import get_project_dir


def find_file(project_dir: str, filename: str) -> str | None:
    """在项目目录下递归查找文件（大小写不敏感）"""
    filename_lower = filename.lower()
    for root, _, files in os.walk(project_dir):
        for f in files:
            if f.lower() == filename_lower:
                return os.path.join(root, f)
    return None


@tool
def export_with_ida(file_hint: str, project_name: str, architecture: str = "") -> dict:
    """
    使用 IDA Pro 分析二进制文件。

    参数:
        file_hint: 文件名或部分路径（如 "lpUds" 或 "bin/lpUds"）
        project_name: 项目名称
        architecture: 可选架构（arm, arm64, x86, x86_64, mips 等）

    返回:
        导出结果
    """
    project_dir = get_project_dir(project_name)
    extractions_dir = os.path.join(project_dir, "extractions")

    if not os.path.exists(extractions_dir):
        return {"error": f"项目未解包，请先执行 /extract: {extractions_dir}"}

    # 1. 查找文件
    target_file = None
    search_name = os.path.basename(file_hint)

    # 先尝试直接作为相对路径查找
    direct_path = os.path.join(extractions_dir, file_hint)
    if os.path.isfile(direct_path):
        target_file = direct_path
    else:
        # 递归查找
        target_file = find_file(extractions_dir, search_name)

    if not target_file:
        return {"error": f"在项目中找不到文件: {file_hint}", "search_path": extractions_dir}

    binary_name = os.path.basename(target_file)
    binary_stem = os.path.splitext(binary_name)[0]

    # 2. 准备输出目录
    export_dir = os.path.join(project_dir, "export-for-ai", binary_stem)
    os.makedirs(export_dir, exist_ok=True)

    # 3. 构建 IDA 命令
    arch_flag = f"-p{architecture}" if architecture else "-parm"  # 默认 ARM
    script_path = os.path.abspath("scripts/ida_export_for_ai.py")

    cmd = [
        "idat",
        "-A",
        arch_flag,
        "-B",
        "-S", f'{script_path} "{export_dir}"',
        target_file,
    ]

    # 4. 执行 - 清理环境避免虚拟环境干扰
    env = os.environ.copy()
    for key in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"):
        env.pop(key, None)

    log_path = os.path.join(export_dir, "ida_export.log")

    try:
        with open(log_path, "w") as log_f:
            result = subprocess.run(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                timeout=3600,
                env=env,
            )
    except subprocess.TimeoutExpired:
        return {"error": "IDA 导出超时", "export_dir": export_dir}
    except FileNotFoundError:
        return {"error": "idat 命令未找到，请确保 IDA Pro 在 PATH 中", "cmd": " ".join(cmd)}
    except Exception as e:
        return {"error": f"执行失败: {e}", "cmd": " ".join(cmd)}

    # 5. 收集结果
    exported_files = []
    for root, _, files in os.walk(export_dir):
        for f in files:
            if f == "ida_export.log":
                continue
            filepath = os.path.join(root, f)
            exported_files.append({
                "name": f,
                "path": os.path.relpath(filepath, export_dir),
                "size": os.path.getsize(filepath),
            })

    # 读取日志
    log_summary = ""
    try:
        with open(log_path, "r", errors="ignore") as f:
            log_summary = "".join(f.readlines()[-50:])
    except Exception:
        pass

    return {
        "binary_name": binary_name,
        "binary_path": target_file,
        "architecture": architecture or "arm",
        "export_dir": export_dir,
        "returncode": result.returncode,
        "exported_files": exported_files,
        "file_count": len(exported_files),
        "log_summary": log_summary,
    }
