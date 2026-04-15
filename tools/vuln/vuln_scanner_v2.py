"""
漏洞扫描器 v2：支持污点分析和按文件生成独立报告。
"""

import json
import os
import re
from typing import Any

from langchain.tools import tool

from core.path_guard import get_project_dir
from tools.vuln.rag_engine import VulnRAG
from tools.vuln.taint_analyzer import analyze_taint, filter_false_positives

# 规则定义（与 v1 保持一致）
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


def _scan_decompile_file(filepath: str, filename: str, rag: VulnRAG) -> list[dict]:
    """扫描单个反编译文件，返回候选漏洞列表"""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        for rule in RULES:
            for pattern in rule["patterns"]:
                if re.search(pattern, stripped, re.IGNORECASE):
                    # 降低 memcpy 的误报
                    if "memcpy" in stripped and ("sizeof" in stripped or stripped.count(",") >= 2):
                        continue
                    
                    rag_knowledge = rag.query(rule["type"])
                    
                    findings.append({
                        "source": "decompile",
                        "file": os.path.join("decompile", filename),
                        "line": line_no,
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "snippet": stripped[:300],
                        "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                        "status": "candidate",  # 初始状态：候选
                    })
                    break
    return findings


def _scan_strings_file(filepath: str, rag: VulnRAG) -> list[dict]:
    """扫描字符串文件"""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_no, line in enumerate(lines, 1):
        line_lower = line.lower()
        for keyword, vuln_type in SENSITIVE_STRINGS.items():
            if keyword in line_lower:
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
                    "snippet": line.strip()[:300],
                    "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                    "status": "candidate",
                })
                break
    return findings


def _scan_imports_file(filepath: str, rag: VulnRAG) -> list[dict]:
    """扫描导入表文件"""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
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
                    "snippet": line.strip()[:300],
                    "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                    "status": "candidate",
                })
                break
    return findings


def _scan_exports_file(filepath: str, binary_name: str, rag: VulnRAG) -> list[dict]:
    """扫描导出表文件"""
    findings = []
    sensitive_patterns = {
        "update": "missing_auth",
        "flash": "missing_auth",
        "diag": "missing_auth",
        "diagnostic": "missing_auth",
        "shell": "command_injection",
        "exec": "command_injection",
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
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
                    "snippet": line.strip()[:300],
                    "rag_knowledge": rag_knowledge[0] if rag_knowledge else {},
                    "status": "candidate",
                })
                break
    return findings


def _save_binary_report(
    report_dir: str,
    binary_name: str,
    findings: list[dict],
    summary: dict,
) -> str:
    """为单个二进制文件保存独立报告"""
    binary_report_dir = os.path.join(report_dir, "vuln_by_binary")
    os.makedirs(binary_report_dir, exist_ok=True)
    
    report_path = os.path.join(binary_report_dir, f"{binary_name}_vuln.json")
    
    report = {
        "binary": binary_name,
        "summary": summary,
        "findings": findings,
        "total_findings": len(findings),
    }
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    
    return report_path


def _save_file_report(
    report_dir: str,
    binary_name: str,
    source_file: str,
    findings: list[dict],
) -> str | None:
    """为单个源文件（如 decompile/xxx.c）保存独立报告"""
    if not findings:
        return None
    
    # 清理文件名，避免路径问题
    safe_name = source_file.replace("/", "_").replace("\\", "_").replace(".", "_")
    
    file_report_dir = os.path.join(report_dir, "vuln_by_file", binary_name)
    os.makedirs(file_report_dir, exist_ok=True)
    
    report_path = os.path.join(file_report_dir, f"{safe_name}_vuln.json")
    
    # 计算摘要
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "medium")
        if sev in severity_count:
            severity_count[sev] += 1
    
    report = {
        "binary": binary_name,
        "source_file": source_file,
        "summary": {
            "total": len(findings),
            **severity_count,
        },
        "findings": findings,
    }
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    
    return report_path


@tool
def scan_vulnerabilities_v2(
    project_name: str,
    enable_taint_analysis: bool = True,
    taint_batch_size: int = 10,
) -> dict:
    """
    扫描项目 export-for-ai/ 目录下的二进制分析结果，支持污点分析和按文件生成独立报告。

    Args:
        project_name: 项目名称
        enable_taint_analysis: 是否启用污点分析（默认启用）
        taint_batch_size: 每批进行污点分析的数量（控制 API 调用频率）

    Returns:
        包含扫描结果、各二进制报告路径、汇总信息的字典
    """
    project_dir = get_project_dir(project_name)
    export_base = os.path.join(project_dir, "export-for-ai")

    if not os.path.exists(export_base):
        return {
            "error": f"未找到导出目录: {export_base}\n请先使用 IDA/Ghidra 导出二进制分析结果。",
        }

    rag = VulnRAG()
    report_dir = os.path.join(project_dir, "report")
    os.makedirs(report_dir, exist_ok=True)

    all_binary_reports = []
    all_confirmed_findings = []
    all_false_positives = []
    scanned_binaries = []

    # 遍历每个二进制导出目录
    for binary_name in sorted(os.listdir(export_base)):
        binary_dir = os.path.join(export_base, binary_name)
        if not os.path.isdir(binary_dir):
            continue

        scanned_binaries.append(binary_name)
        print(f"[VulnScan] 正在扫描二进制: {binary_name}")

        decompile_dir = os.path.join(binary_dir, "decompile")
        strings_path = os.path.join(binary_dir, "strings.txt")
        imports_path = os.path.join(binary_dir, "imports.txt")
        exports_path = os.path.join(binary_dir, "exports.txt")

        # 1. 规则扫描 - 收集候选漏洞
        candidate_findings = []
        
        # 扫描 decompile 目录下的每个 .c 文件
        if os.path.exists(decompile_dir):
            for filename in os.listdir(decompile_dir):
                if filename.endswith(".c"):
                    filepath = os.path.join(decompile_dir, filename)
                    findings = _scan_decompile_file(filepath, filename, rag)
                    candidate_findings.extend(findings)

        # 扫描其他文件
        if os.path.exists(strings_path):
            candidate_findings.extend(_scan_strings_file(strings_path, rag))
        if os.path.exists(imports_path):
            candidate_findings.extend(_scan_imports_file(imports_path, rag))
        if os.path.exists(exports_path):
            candidate_findings.extend(_scan_exports_file(exports_path, binary_name, rag))

        # 标记所属二进制
        for f in candidate_findings:
            f["binary"] = binary_name

        print(f"[VulnScan] {binary_name}: 发现 {len(candidate_findings)} 个候选漏洞")

        # 2. 污点分析（如果启用）
        if enable_taint_analysis and candidate_findings:
            print(f"[VulnScan] {binary_name}: 开始进行污点分析...")
            
            for i, finding in enumerate(candidate_findings):
                if i > 0 and i % taint_batch_size == 0:
                    print(f"[VulnScan] 已分析 {i}/{len(candidate_findings)} 个候选漏洞...")
                
                taint_result = analyze_taint(finding, project_name, binary_name)
                finding["taint_analysis"] = taint_result
                
                # 根据分析结果更新状态
                exploitability = taint_result.get("exploitability", "unknown")
                if exploitability == "false_positive":
                    finding["status"] = "false_positive"
                elif exploitability in ["confirmed", "likely"]:
                    finding["status"] = "confirmed"
                else:
                    finding["status"] = "uncertain"

            # 分离确认漏洞和误报
            confirmed, false_pos = filter_false_positives(candidate_findings)
            print(f"[VulnScan] {binary_name}: 确认 {len(confirmed)} 个，误报 {len(false_pos)} 个，待复核 {len(candidate_findings) - len(confirmed) - len(false_pos)} 个")
        else:
            confirmed = candidate_findings
            false_pos = []

        all_confirmed_findings.extend(confirmed)
        all_false_positives.extend(false_pos)

        # 3. 生成二进制级报告
        binary_summary = {
            "total_candidates": len(candidate_findings),
            "confirmed": len(confirmed),
            "false_positives": len(false_pos),
            "severity": {
                "critical": sum(1 for f in confirmed if f.get("severity") == "critical"),
                "high": sum(1 for f in confirmed if f.get("severity") == "high"),
                "medium": sum(1 for f in confirmed if f.get("severity") == "medium"),
                "low": sum(1 for f in confirmed if f.get("severity") == "low"),
            }
        }
        
        binary_report_path = _save_binary_report(
            report_dir, binary_name, confirmed, binary_summary
        )
        
        # 4. 生成文件级报告（按源文件分组）
        file_reports = {}
        for finding in confirmed:
            source_file = finding.get("file", "unknown")
            if source_file not in file_reports:
                file_reports[source_file] = []
            file_reports[source_file].append(finding)
        
        file_report_paths = []
        for source_file, findings in file_reports.items():
            path = _save_file_report(report_dir, binary_name, source_file, findings)
            if path:
                file_report_paths.append(path)

        all_binary_reports.append({
            "binary": binary_name,
            "binary_report": binary_report_path,
            "file_reports": file_report_paths,
            "summary": binary_summary,
        })

    # 5. 生成总报告
    master_summary = {
        "total_binaries": len(scanned_binaries),
        "total_confirmed": len(all_confirmed_findings),
        "total_false_positives": len(all_false_positives),
        "severity_distribution": {
            "critical": sum(1 for f in all_confirmed_findings if f.get("severity") == "critical"),
            "high": sum(1 for f in all_confirmed_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in all_confirmed_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in all_confirmed_findings if f.get("severity") == "low"),
        }
    }
    
    master_report = {
        "project": project_name,
        "summary": master_summary,
        "scanned_binaries": scanned_binaries,
        "binary_reports": all_binary_reports,
        "all_confirmed_findings": all_confirmed_findings,
        "all_false_positives": all_false_positives,
    }
    
    master_report_path = os.path.join(report_dir, "vuln_scan_master.json")
    with open(master_report_path, "w", encoding="utf-8") as f:
        json.dump(master_report, f, ensure_ascii=False, indent=2, default=str)

    return {
        "project": project_name,
        "export_dir": export_base,
        "scanned_binaries": scanned_binaries,
        "summary": master_summary,
        "master_report": master_report_path,
        "binary_reports": all_binary_reports,
        "confirmed_findings_count": len(all_confirmed_findings),
        "false_positive_count": len(all_false_positives),
    }
