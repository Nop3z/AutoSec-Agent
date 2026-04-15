import os
import re

from langchain.tools import tool

from core.path_guard import get_project_dir
from tools.vuln.rag_engine import VulnRAG

# 规则定义
RULES = [
    {
        "type": "command_injection",
        "severity": "critical",
        "patterns": [r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexec\w*\s*\(", r"\beval\s*\("],
        "description": "用户输入直接拼接到系统命令执行函数中",
    },
    {
        "type": "buffer_overflow",
        "severity": "high",
        "patterns": [r"\bstrcpy\s*\(", r"\bstrcat\s*\(", r"\bsprintf\s*\(", r"\bgets\s*\("],
        "description": "使用了不安全的字符串/内存拷贝函数，可能导致缓冲区溢出",
    },
    {
        "type": "format_string",
        "severity": "high",
        "patterns": [r"\bprintf\s*\(", r"\bfprintf\s*\(", r"\bsprintf\s*\("],
        "description": "格式化字符串函数可能直接使用了用户输入作为格式串",
    },
    {
        "type": "arbitrary_file_read",
        "severity": "medium",
        "patterns": [r"\bfopen\s*\(", r"\bopen\s*\(", r"\baccess\s*\(", r"\bstat\s*\("],
        "description": "文件操作函数使用了可能来自用户输入的路径参数",
    },
    {
        "type": "hardcoded_credential",
        "severity": "high",
        "patterns": [
            r"password\s*=\s*['\"]",
            r"passwd\s*=\s*['\"]",
            r"secret\s*=\s*['\"]",
            r"token\s*=\s*['\"]",
            r"api_key\s*=\s*['\"]",
        ],
        "description": "代码或字符串表中可能存在硬编码的敏感凭证",
    },
    {
        "type": "insecure_crypto",
        "severity": "medium",
        "patterns": [r"\bDES_", r"\bMD5_", r"\bRC4_", r"\bAES_set_encrypt_key"],
        "description": "使用了已知不安全的加密算法或模式",
    },
]

# 危险导入函数
DANGEROUS_IMPORTS = {
    "system": "command_injection",
    "popen": "command_injection",
    "strcpy": "buffer_overflow",
    "strcat": "buffer_overflow",
    "sprintf": "buffer_overflow",
    "gets": "buffer_overflow",
    "memcpy": "buffer_overflow",
    "printf": "format_string",
    "fopen": "arbitrary_file_read",
    "open": "arbitrary_file_read",
}

# 敏感字符串模式
SENSITIVE_STRINGS = {
    "password": "hardcoded_credential",
    "passwd": "hardcoded_credential",
    "secret": "hardcoded_credential",
    "token": "hardcoded_credential",
    "api_key": "hardcoded_credential",
    "private_key": "hardcoded_credential",
    "admin": "hardcoded_credential",
    "root": "hardcoded_credential",
}


def _scan_decompile(decompile_dir: str, rag: VulnRAG) -> list[dict]:
    """扫描反编译代码文件"""
    findings = []
    if not os.path.exists(decompile_dir):
        return findings

    for filename in os.listdir(decompile_dir):
        if not filename.endswith(".c"):
            continue
        filepath = os.path.join(decompile_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, IOError):
            continue

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            for rule in RULES:
                for pattern in rule["patterns"]:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # 降低 memcpy 的误报：检查是否有 sizeof 或长度参数
                        if "memcpy" in stripped and ("sizeof" in stripped or stripped.count(",") >= 2):
                            continue
                        
                        # 获取 RAG 知识
                        rag_knowledge = rag.query(rule["type"])
                        
                        findings.append({
                            "source": "decompile",
                            "file": os.path.join("decompile", filename),
                            "line": line_no,
                            "type": rule["type"],
                            "severity": rule["severity"],
                            "snippet": stripped[:200],
                            "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                        })
                        break  # 同一行同一类型只报一次
    return findings


def _scan_strings(strings_path: str, rag: VulnRAG) -> list[dict]:
    """扫描字符串表中的敏感信息"""
    findings = []
    if not os.path.exists(strings_path):
        return findings

    try:
        with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_no, line in enumerate(lines, 1):
        line_lower = line.lower()
        for keyword, vuln_type in SENSITIVE_STRINGS.items():
            if keyword in line_lower:
                # 过滤掉过短的字符串（误报）
                parts = line.strip().split("|")
                if len(parts) >= 4:
                    str_content = parts[-1].strip()
                    if len(str_content) < 4:
                        continue
                
                rag_knowledge = rag.query(vuln_type)
                findings.append({
                    "source": "strings",
                    "file": "strings.txt",
                    "line": line_no,
                    "type": vuln_type,
                    "severity": "medium",
                    "snippet": line.strip()[:200],
                    "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                })
                break
    return findings


def _scan_imports(imports_path: str, rag: VulnRAG) -> list[dict]:
    """扫描导入表中的危险函数"""
    findings = []
    if not os.path.exists(imports_path):
        return findings

    try:
        with open(imports_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_no, line in enumerate(lines, 1):
        line_lower = line.lower()
        for func, vuln_type in DANGEROUS_IMPORTS.items():
            if func in line_lower:
                rag_knowledge = rag.query(vuln_type)
                findings.append({
                    "source": "imports",
                    "file": "imports.txt",
                    "line": line_no,
                    "type": vuln_type,
                    "severity": "medium",
                    "snippet": line.strip()[:200],
                    "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                })
                break
    return findings


def _scan_exports(exports_path: str, binary_name: str, rag: VulnRAG) -> list[dict]:
    """扫描导出表中是否有敏感接口暴露"""
    findings = []
    if not os.path.exists(exports_path):
        return findings

    sensitive_patterns = {
        "update": "missing_auth",
        "flash": "missing_auth",
        "diag": "missing_auth",
        "diagnostic": "missing_auth",
        "shell": "command_injection",
        "exec": "command_injection",
    }

    try:
        with open(exports_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_no, line in enumerate(lines, 1):
        line_lower = line.lower()
        for pattern, vuln_type in sensitive_patterns.items():
            if pattern in line_lower:
                rag_knowledge = rag.query(vuln_type)
                findings.append({
                    "source": "exports",
                    "file": "exports.txt",
                    "line": line_no,
                    "type": vuln_type,
                    "severity": "high",
                    "snippet": line.strip()[:200],
                    "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                })
                break
    return findings


@tool
def scan_vulnerabilities(project_name: str) -> dict:
    """
    扫描项目 export-for-ai/ 目录下所有已导出的二进制分析结果，
    寻找潜在漏洞（命令注入、缓冲区溢出、格式化字符串、硬编码凭证等）。

    参数:
        project_name: 项目名称

    返回:
        包含所有漏洞发现、统计信息、报告路径的字典
    """
    project_dir = get_project_dir(project_name)
    export_base = os.path.join(project_dir, "export-for-ai")

    if not os.path.exists(export_base):
        return {
            "error": f"未找到导出目录: {export_base}\n请先使用 IDA Pro 导出二进制分析结果。",
        }

    rag = VulnRAG()
    all_findings = []
    scanned_binaries = []

    # 遍历每个二进制导出目录
    for binary_name in sorted(os.listdir(export_base)):
        binary_dir = os.path.join(export_base, binary_name)
        if not os.path.isdir(binary_dir):
            continue

        scanned_binaries.append(binary_name)
        decompile_dir = os.path.join(binary_dir, "decompile")
        strings_path = os.path.join(binary_dir, "strings.txt")
        imports_path = os.path.join(binary_dir, "imports.txt")
        exports_path = os.path.join(binary_dir, "exports.txt")

        findings = []
        findings.extend(_scan_decompile(decompile_dir, rag))
        findings.extend(_scan_strings(strings_path, rag))
        findings.extend(_scan_imports(imports_path, rag))
        findings.extend(_scan_exports(exports_path, binary_name, rag))

        # 标记属于哪个二进制
        for f in findings:
            f["binary"] = binary_name

        all_findings.extend(findings)

    # 统计
    summary = {
        "total": len(all_findings),
        "scanned_binaries": scanned_binaries,
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "low"),
    }

    # 保存结构化报告
    report_dir = os.path.join(project_dir, "report")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "vuln_scan.json")
    import json
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "project": project_name,
            "summary": summary,
            "findings": all_findings,
        }, f, ensure_ascii=False, indent=2, default=str)

    return {
        "project": project_name,
        "export_dir": export_base,
        "scanned_binaries": scanned_binaries,
        "summary": summary,
        "findings": all_findings,
        "report_path": report_path,
    }
