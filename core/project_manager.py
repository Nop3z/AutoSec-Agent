import os
import shutil

OUTPUT_BASE = "data/outputs"


def create_project(project_name: str) -> str:
    """
    创建项目目录结构：
    data/outputs/{project_name}/
    ├── report/
    └── Certificate/
    返回项目根目录的绝对路径。
    """
    project_dir = os.path.abspath(os.path.join(OUTPUT_BASE, project_name))
    os.makedirs(os.path.join(project_dir, "report"), exist_ok=True)
    os.makedirs(os.path.join(project_dir, "Certificate"), exist_ok=True)
    # 确保 Docker 容器有写权限
    os.chmod(project_dir, 0o777)
    os.chmod(os.path.join(project_dir, "report"), 0o777)
    os.chmod(os.path.join(project_dir, "Certificate"), 0o777)
    return project_dir


def prepare_firmware(project_dir: str, firmware_path: str) -> str:
    """
    将固件文件复制到项目目录内，返回复制后的文件名。
    """
    firmware_name = os.path.basename(firmware_path)
    dest = os.path.join(project_dir, firmware_name)
    shutil.copy2(os.path.abspath(firmware_path), dest)
    return firmware_name
