"""
交叉引用分析工具：让 Agent 自主读取反编译代码和查询调用关系。

提供两个 LangChain Tool：
1. read_decompiled_function - 读取指定函数的反编译代码
2. lookup_function_xrefs - 查询函数的交叉引用关系（callers/callees）
"""

import os
import re
from typing import Any

from langchain.tools import tool

from core.path_guard import get_project_dir


def _addr_to_filename(address: str) -> str:
    addr = address.replace("0x", "").replace("0X", "").upper()
    return f"{addr}.c"


def parse_function_index(index_path: str) -> dict[str, dict[str, Any]]:
    """
    解析 function_index.txt，返回两个索引：
    - by_address: {address: {name, file, callers, callees}}
    - by_name: {name: address}
    """
    by_address: dict[str, dict[str, Any]] = {}
    by_name: dict[str, str] = {}

    if not os.path.exists(index_path):
        return by_address, by_name

    with open(index_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    blocks = content.split("=" * 80)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        name_match = re.search(r"Function:\s*(\S+)", block)
        addr_match = re.search(r"Address:\s*(0x[0-9a-fA-F]+)", block)
        file_match = re.search(r"File:\s*(\S+\.c)", block)

        if not addr_match:
            continue

        address = addr_match.group(1).lower()
        func_name = name_match.group(1) if name_match else f"sub_{address}"
        file_name = file_match.group(1) if file_match else _addr_to_filename(address)

        callers = []
        callees = []

        caller_section = re.search(
            r"Called by.*?(?=Calls|$)", block, re.DOTALL
        )
        if caller_section:
            for m in re.finditer(
                r"(0x[0-9a-fA-F]+)\s*\((\w+)\)\s*->\s*(\S+\.c)",
                caller_section.group(0),
            ):
                callers.append(
                    {"address": m.group(1).lower(), "name": m.group(2), "file": m.group(3)}
                )

        callee_section = re.search(r"Calls.*", block, re.DOTALL)
        if callee_section:
            for m in re.finditer(
                r"(0x[0-9a-fA-F]+)\s*\((\w+)\)\s*->\s*(\S+\.c)",
                callee_section.group(0),
            ):
                callees.append(
                    {"address": m.group(1).lower(), "name": m.group(2), "file": m.group(3)}
                )

        entry = {
            "name": func_name,
            "address": address,
            "file": file_name,
            "callers": callers,
            "callees": callees,
        }
        by_address[address] = entry
        by_name[func_name.lower()] = address

    return by_address, by_name


# ---- 模块级缓存 ----
_index_cache: dict[str, tuple[dict, dict]] = {}


def _get_index(project_name: str, binary_name: str) -> tuple[dict, dict]:
    cache_key = f"{project_name}/{binary_name}"
    if cache_key not in _index_cache:
        project_dir = get_project_dir(project_name)
        index_path = os.path.join(
            project_dir, "export-for-ai", binary_name, "function_index.txt"
        )
        _index_cache[cache_key] = parse_function_index(index_path)
    return _index_cache[cache_key]


MAX_LINES = 200


@tool
def read_decompiled_function(
    project_name: str,
    binary_name: str,
    identifier: str,
) -> str:
    """
    读取一个反编译函数的完整源码。

    Args:
        project_name: 项目名称（如 "LP-TBOX"）
        binary_name: 二进制名称（如 "libcmcc_sdk"）
        identifier: 文件名（如 "3068.c"）或函数地址（如 "0x3068"）或函数名（如 "ThreadNetworkDiagno"）

    Returns:
        反编译源码文本（包含头部注释中的 callers/callees 信息）
    """
    project_dir = get_project_dir(project_name)
    decompile_dir = os.path.join(
        project_dir, "export-for-ai", binary_name, "decompile"
    )

    if not os.path.isdir(decompile_dir):
        return f"错误: 未找到反编译目录 {decompile_dir}"

    # 确定文件名
    if identifier.endswith(".c"):
        file_name = identifier
    elif identifier.startswith("0x") or identifier.startswith("0X"):
        file_name = _addr_to_filename(identifier)
    else:
        by_address, by_name = _get_index(project_name, binary_name)
        addr = by_name.get(identifier.lower())
        if addr and addr in by_address:
            file_name = by_address[addr]["file"]
        else:
            file_name = f"{identifier}.c"

    filepath = os.path.join(decompile_dir, file_name)

    if not os.path.isfile(filepath):
        return f"错误: 未找到文件 {file_name}（尝试路径: {filepath}）"

    real = os.path.realpath(filepath)
    if not real.startswith(os.path.realpath(project_dir)):
        return "错误: 路径越界，拒绝访问"

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if len(lines) > MAX_LINES:
        text = "".join(lines[:MAX_LINES])
        text += f"\n\n... [截断: 共 {len(lines)} 行，仅显示前 {MAX_LINES} 行]"
        return text

    return "".join(lines)


@tool
def lookup_function_xrefs(
    project_name: str,
    binary_name: str,
    identifier: str,
) -> dict:
    """
    查询一个函数的交叉引用关系：谁调用了它（callers），它调用了谁（callees）。

    Args:
        project_name: 项目名称（如 "LP-TBOX"）
        binary_name: 二进制名称（如 "libcmcc_sdk"）
        identifier: 函数名（如 "ThreadNetworkDiagno"）或地址（如 "0x3068"）

    Returns:
        包含 callers 和 callees 列表的字典，每项有 name/address/file 字段
    """
    by_address, by_name = _get_index(project_name, binary_name)

    # 尝试按地址查找
    if identifier.startswith("0x") or identifier.startswith("0X"):
        addr = identifier.lower()
        entry = by_address.get(addr)
    else:
        # 按名称查找
        addr = by_name.get(identifier.lower())
        entry = by_address.get(addr) if addr else None

    if not entry:
        return {
            "error": f"未找到函数 '{identifier}'",
            "hint": "可用地址格式（如 0x3068）或函数名（如 ThreadNetworkDiagno）",
        }

    return {
        "function": entry["name"],
        "address": entry["address"],
        "file": entry["file"],
        "callers": entry["callers"],
        "callees": entry["callees"],
        "caller_count": len(entry["callers"]),
        "callee_count": len(entry["callees"]),
    }
