import os
import subprocess
import shutil

from langchain.tools import tool

from core.project_manager import create_project
from core.path_guard import get_project_dir, is_within_project


@tool
def extract_firmware(firmware_path: str, project_name: str) -> dict:
    """
    使用 binwalkv3 (Docker) 对固件进行自动解包。

    参数:
        firmware_path: 原始固件文件的路径（如 firmware.bin），或已解压的目录
        project_name: 用户命名的项目名称

    返回:
        包含项目目录、extractions 目录、解包文件列表等信息的字典
    """
    # 路径安全检查：firmware_path 必须在项目目录内，或者是本机合法路径（用于首次导入）
    project_dir = get_project_dir(project_name)
    
    # 如果传入的路径已经在项目目录内，直接允许
    if not is_within_project(firmware_path, project_dir):
        # 如果不在项目内，必须是已存在的文件（首次导入），我们会复制它进去
        if not os.path.exists(firmware_path):
            return {"error": f"固件路径不存在: {firmware_path}"}
        # 首次导入：允许任意路径，但后续操作都在项目内
    
    # 1. 创建项目目录结构
    project_dir = create_project(project_name)
    extractions_dir = os.path.join(project_dir, "extractions")
    firmware_name = os.path.basename(firmware_path)

    # 2. 判断传入的是文件还是目录
    if os.path.isdir(firmware_path):
        # 检查是否在项目目录内
        if not is_within_project(firmware_path, project_dir):
            return {"error": f"目录 '{firmware_path}' 不在项目 '{project_dir}' 内，拒绝访问"}
        
        # 目录：直接复制内容到 extractions/ 下，跳过 binwalk
        if os.path.exists(extractions_dir):
            for item in os.listdir(extractions_dir):
                item_path = os.path.join(extractions_dir, item)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
        os.makedirs(extractions_dir, exist_ok=True)
        for item in os.listdir(firmware_path):
            src = os.path.join(firmware_path, item)
            dst = os.path.join(extractions_dir, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

        extracted_files = []
        for root, _, files in os.walk(extractions_dir):
            for f in files:
                extracted_files.append(os.path.relpath(os.path.join(root, f), extractions_dir))

        return {
            "project_name": project_name,
            "project_dir": project_dir,
            "extractions_dir": extractions_dir,
            "firmware_name": firmware_name,
            "extracted_files": extracted_files,
            "extracted_count": len(extracted_files),
            "note": "传入的是目录，已直接复制到 extractions/，跳过 binwalk 解包。",
        }

    # 3. 文件：复制到项目目录，再 Docker 解包
    # 检查文件是否在项目内，如果不在则复制进去
    dest = os.path.join(project_dir, firmware_name)
    if is_within_project(firmware_path, project_dir):
        # 已经在项目内，直接使用
        if firmware_path != dest:
            shutil.copy2(os.path.abspath(firmware_path), dest)
    else:
        # 首次导入：从外部复制到项目目录
        shutil.copy2(os.path.abspath(firmware_path), dest)

    # 对齐官方命令：sudo docker run -t -v "$PWD":/analysis binwalkv3 -Me firmware.bin
    cmd = [
        "sudo", "docker", "run", "-t",
        "-v", f"{project_dir}:/analysis",
        "binwalkv3",
        "-Me", firmware_name,
    ]

    log_path = os.path.join(project_dir, "binwalk.log")
    try:
        with open(log_path, "w") as log_f:
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                stdout=log_f,
                stderr=subprocess.STDOUT,
            )
    except Exception as e:
        return {
            "error": f"启动解包进程失败: {e}",
            "project_dir": project_dir,
        }

    if result.returncode != 0:
        log_content = ""
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                log_content = f.read()
        return {
            "error": "固件解包失败",
            "returncode": result.returncode,
            "log": log_content,
            "project_dir": project_dir,
        }

    # 4. binwalk 输出到 extractions/，直接使用，不再改名
    extracted_files = []
    if os.path.exists(extractions_dir):
        for root, _, files in os.walk(extractions_dir):
            for f in files:
                extracted_files.append(os.path.relpath(os.path.join(root, f), extractions_dir))

    return {
        "project_name": project_name,
        "project_dir": project_dir,
        "extractions_dir": extractions_dir,
        "firmware_name": firmware_name,
        "extracted_files": extracted_files,
        "extracted_count": len(extracted_files),
    }
