import os
from pathlib import Path

from dotenv import load_dotenv

# 加载 .env 文件
load_dotenv()


def get_ida_path() -> str:
    """
    获取 IDA Pro 的安装路径。
    优先从环境变量 IDA_PATH 读取，否则返回默认值。
    """
    ida_path = os.getenv("IDA_PATH", "")
    if ida_path and os.path.exists(ida_path):
        return ida_path
    
    # 默认常见安装路径（macOS）
    default_paths = [
        "/Applications/IDA Pro 8.4/idat",
        "/Applications/IDA Pro 8.3/idat",
        "/Applications/IDA Pro 8.2/idat",
        "/Applications/IDA Pro 8.1/idat",
        "/Applications/IDA Pro 8.0/idat",
        "/Applications/IDA Pro 7.7/idat",
        "/Applications/IDA Pro 7.6/idat",
        # Linux 常见路径
        "/opt/idapro/idat",
        "/usr/local/bin/idat",
        # Windows (通过 Wine 或原生)
        "C:\\Program Files\\IDA Pro 8.4\\idat.exe",
        "C:\\Program Files\\IDA Pro 8.3\\idat.exe",
    ]
    
    for path in default_paths:
        if os.path.exists(path):
            return path
    
    return "idat"  # 最后尝试从 PATH 找


def get_ida_script_path() -> str:
    """获取 IDA 导出脚本的路径"""
    # 脚本放在项目根目录的 scripts/ 下
    project_root = Path(__file__).parent.parent
    script_path = project_root / "scripts" / "ida_export_for_ai.py"
    return str(script_path)


# 架构到 IDA 参数的映射
ARCHITECTURE_MAP = {
    "arm": "-parm",
    "arm64": "-parm64",
    "aarch64": "-parm64",
    "x86": "-px86",
    "x86_64": "-px86_64",
    "amd64": "-px86_64",
    "mips": "-pmips",
    "mips64": "-pmips64",
    "ppc": "-pppc",
    "ppc64": "-pppc64",
    "riscv": "-priscv",
    "riscv64": "-priscv64",
    "sparc": "-psparc",
    "sparc64": "-psparc64",
}


def get_arch_param(arch: str) -> str:
    """
    将架构名称转换为 IDA 命令行参数。
    如果未知，返回空字符串（让 IDA 自动检测）。
    """
    arch_lower = arch.lower().strip()
    return ARCHITECTURE_MAP.get(arch_lower, "")
