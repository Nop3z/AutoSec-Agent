"""
专用漏洞分析工作流 - 按漏洞类型拆分
输出格式: sub1(char* a) → sub2(char* b) → sub3(char* c)
报告结构: report/<binary>/<vuln-type>/
"""

import json
import os
import re

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.path_guard import get_project_dir
from core.state import AutoSecState


CMD_INJECTION_PROMPT = """
你是命令注入漏洞分析专家，专注于分析 system(), popen(), exec*() 等危险函数调用。

## 任务
1. 分析每个漏洞的调用链
2. 确认参数是否用户可控
3. 给出利用建议和修复方案

## 输出格式要求
每个漏洞必须包含:
- 调用链 (call_chain): func1(param) → func2(param) → vulnerable_func(param)
- 参数来源 (param_source)
- 利用场景 (exploit_scenario)
- 修复建议 (remediation)
"""

BUFFER_OVERFLOW_PROMPT = """
你是缓冲区溢出漏洞分析专家，专注于分析 strcpy, strcat, sprintf, memcpy 等危险函数。

## 任务
1. 分析每个漏洞的调用链
2. 确认缓冲区大小和输入长度关系
3. 给出利用建议和修复方案

## 输出格式要求
每个漏洞必须包含:
- 调用链 (call_chain): func1(param) → func2(param) → vulnerable_func(param)
- 缓冲区大小 (buffer_size)
- 利用场景 (exploit_scenario)
- 修复建议 (remediation)
"""

FORMAT_STRING_PROMPT = """
你是格式化字符串漏洞分析专家，专注于分析 printf, fprintf, sprintf 等函数的不安全使用。

## 任务
1. 分析每个漏洞的调用链
2. 确认格式串是否用户可控
3. 给出利用建议和修复方案

## 输出格式要求
每个漏洞必须包含:
- 调用链 (call_chain): func1(param) → func2(param) → vulnerable_func(param)
- 格式串来源 (format_source)
- 利用场景 (exploit_scenario)
- 修复建议 (remediation)
"""

FILE_OPERATION_PROMPT = """
你是文件操作漏洞分析专家，专注于分析 fopen, open 等函数的路径遍历漏洞。

## 任务
1. 分析每个漏洞的调用链
2. 确认文件路径是否用户可控
3. 给出利用建议和修复方案

## 输出格式要求
每个漏洞必须包含:
- 调用链 (call_chain): func1(param) → func2(param) → vulnerable_func(param)
- 路径来源 (path_source)
- 利用场景 (exploit_scenario)
- 修复建议 (remediation)
"""


cmd_injection_agent = create_agent(model, tools=[], system_prompt=CMD_INJECTION_PROMPT)
buffer_overflow_agent = create_agent(model, tools=[], system_prompt=BUFFER_OVERFLOW_PROMPT)
format_string_agent = create_agent(model, tools=[], system_prompt=FORMAT_STRING_PROMPT)
file_operation_agent = create_agent(model, tools=[], system_prompt=FILE_OPERATION_PROMPT)


def _parse_function_header(filepath: str) -> dict:
    """
    解析反编译文件头部的注释信息
    格式:
    /*
     * func-name: sub_77D28
     * func-address: 0x77d28
     * callers: 0x77e08, 0x77fcc
     * callees: 0xf274, 0xf3e8
     */
    """
    info = {
        "func_name": None,
        "func_address": None,
        "callers": [],  # 调用本函数的地址列表
        "callees": [],  # 本函数调用的地址列表
        "params": [],
    }
    
    if not os.path.exists(filepath):
        return info
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except:
        return info
    
    # 提取头部注释
    header_match = re.search(r"/\*(.*?)\*/", content, re.DOTALL)
    if not header_match:
        return info
    
    header = header_match.group(1)
    
    # 提取 func-name
    name_match = re.search(r"func-name:\s*(\w+)", header)
    if name_match:
        info["func_name"] = name_match.group(1)
    
    # 提取 func-address
    addr_match = re.search(r"func-address:\s*(0x[0-9a-fA-F]+)", header)
    if addr_match:
        info["func_address"] = addr_match.group(1)
    
    # 提取 callers (可能多个)
    callers_match = re.search(r"callers:\s*([0-9a-fA-Fx,\s]+)", header)
    if callers_match:
        callers_str = callers_match.group(1)
        info["callers"] = [c.strip() for c in callers_str.split(",") if c.strip()]
    
    # 提取 callees
    callees_match = re.search(r"callees:\s*([0-9a-fA-Fx,\s]+)", header)
    if callees_match:
        callees_str = callees_match.group(1)
        info["callees"] = [c.strip() for c in callees_str.split(",") if c.strip()]
    
    # 提取函数参数 (从函数定义)
    func_def_match = re.search(r"(int|bool|void)\s+\w+\s*\(([^)]*)\)", content)
    if func_def_match:
        params_str = func_def_match.group(2)
        for param in params_str.split(","):
            param = param.strip()
            if param and param != "void":
                # 提取参数名 (最后一个单词)
                parts = param.split()
                if len(parts) >= 2:
                    info["params"].append(parts[-1].replace("*", ""))
    
    return info


def _find_file_by_address(decompile_dir: str, address: str) -> str:
    """
    根据函数地址查找对应的文件
    地址格式: 0x77e08 -> 77E08.c
    """
    # 去掉 0x 前缀，转大写
    addr_clean = address.replace("0x", "").upper()
    filename = f"{addr_clean}.c"
    
    if os.path.exists(os.path.join(decompile_dir, filename)):
        return filename
    
    # 尝试小写
    filename_lower = f"{addr_clean.lower()}.c"
    if os.path.exists(os.path.join(decompile_dir, filename_lower)):
        return filename_lower
    
    return None


def _extract_variable_assignments(filepath: str, target_var: str) -> list:
    """
    从文件中提取目标变量的赋值语句
    返回: [(line_no, assigned_value), ...]
    """
    assignments = []
    
    if not os.path.exists(filepath):
        return assignments
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except:
        return assignments
    
    # 匹配赋值语句: var = value; 或 var = func(...);
    pattern = rf"\b{re.escape(target_var)}\s*=\s*([^;]+);"
    
    for line_no, line in enumerate(lines, 1):
        match = re.search(pattern, line)
        if match:
            value = match.group(1).strip()
            assignments.append((line_no, value))
    
    return assignments


def _find_parameter_source(decompile_dir: str, func_file: str, param_name: str, max_depth: int = 3) -> dict:
    """
    追踪参数的来源
    
    返回: {
        "source_type": "user_input" | "file_read" | "network" | "unknown",
        "source_location": "file.c:line",
        "source_code": "...",
        "propagation_chain": [(func1, param1), (func2, param2), ...]
    }
    """
    result = {
        "source_type": "unknown",
        "source_location": None,
        "source_code": None,
        "propagation_chain": [],
    }
    
    if not param_name or param_name in ["unknown", "void"]:
        return result
    
    current_file = func_file
    current_param = param_name
    depth = 0
    
    while current_file and depth < max_depth:
        filepath = os.path.join(decompile_dir, current_file)
        
        # 1. 在当前函数中查找参数的赋值
        assignments = _extract_variable_assignments(filepath, current_param)
        
        for line_no, value in assignments:
            result["propagation_chain"].append({
                "file": current_file,
                "line": line_no,
                "param": current_param,
                "value": value[:100],
            })
            
            # 检查值的类型
            value_lower = value.lower()
            
            # 用户输入相关
            if any(kw in value_lower for kw in ["getvalue", "getenv", "argv", "stdin"]):
                result["source_type"] = "user_input"
                result["source_location"] = f"{current_file}:{line_no}"
                result["source_code"] = value[:200]
                return result
            
            # 网络相关
            if any(kw in value_lower for kw in ["recv", "socket", "http", "cgi", "webs"]):
                result["source_type"] = "network"
                result["source_location"] = f"{current_file}:{line_no}"
                result["source_code"] = value[:200]
                return result
            
            # 文件读取
            if any(kw in value_lower for kw in ["fread", "fgets", "read(", "nvram_get"]):
                result["source_type"] = "file_read"
                result["source_location"] = f"{current_file}:{line_no}"
                result["source_code"] = value[:200]
                return result
            
            # 如果是函数调用，继续追踪返回值
            func_call_match = re.search(r"(\w+)\s*\(", value)
            if func_call_match:
                called_func = func_call_match.group(1)
                # 在当前文件中查找这个函数的定义
                # 简化处理：假设返回值赋给了当前参数
                continue
        
        # 2. 查找调用者，继续向上追踪
        info = _parse_function_header(filepath)
        
        if info["callers"]:
            caller_addr = info["callers"][0]
            caller_file = _find_file_by_address(decompile_dir, caller_addr)
            
            if caller_file and caller_file != current_file:
                # 在调用者中查找对当前函数的调用，确定参数传递
                caller_path = os.path.join(decompile_dir, caller_file)
                try:
                    with open(caller_path, "r", encoding="utf-8", errors="ignore") as f:
                        caller_content = f.read()
                except:
                    break
                
                # 查找函数调用，提取传递的参数
                current_func_name = info["func_name"] or f"sub_{current_file.replace('.c', '')}"
                call_pattern = rf"{re.escape(current_func_name)}\s*\(([^)]+)\)"
                call_match = re.search(call_pattern, caller_content)
                
                if call_match:
                    args_str = call_match.group(1)
                    args = [a.strip() for a in args_str.split(",")]
                    
                    # 找到当前参数在参数列表中的位置
                    if info["params"] and current_param in info["params"]:
                        param_idx = info["params"].index(current_param)
                        if param_idx < len(args):
                            # 更新当前参数为调用者传递的参数
                            current_param = args[param_idx]
                            result["propagation_chain"].append({
                                "file": caller_file,
                                "param": current_param,
                                "note": f"passed from caller as arg {param_idx}",
                            })
                
                current_file = caller_file
                depth += 1
            else:
                break
        else:
            # 没有调用者，检查是否是入口函数
            if info["params"] and current_param in info["params"]:
                result["source_type"] = "user_input"
                result["source_location"] = f"{current_file}:entry"
                result["source_code"] = f"function parameter: {current_param}"
            break
    
    return result


def _build_call_chain(decompile_dir: str, target_file: str, vuln_func: str, param: str, max_depth: int = 5) -> dict:
    """
    递归构建完整调用链和参数追踪
    
    返回: {
        "call_chain": "func1() → func2() → vuln_func(param)",
        "param_trace": {参数追踪结果}
    }
    """
    chain = []
    
    # 解析当前文件
    current_file = target_file
    current_depth = 0
    
    while current_file and current_depth < max_depth:
        filepath = os.path.join(decompile_dir, current_file)
        info = _parse_function_header(filepath)
        
        if not info["func_name"]:
            info["func_name"] = f"sub_{current_file.replace('.c', '')}"
        
        # 构建函数签名
        if info["params"]:
            params_str = ", ".join([f"char* {p}" for p in info["params"]])
        else:
            params_str = "void"
        
        func_sig = f"{info['func_name']}({params_str})"
        chain.insert(0, func_sig)
        
        # 查找调用者
        if info["callers"]:
            caller_addr = info["callers"][0]
            caller_file = _find_file_by_address(decompile_dir, caller_addr)
            
            if caller_file and caller_file != current_file:
                current_file = caller_file
                current_depth += 1
            else:
                break
        else:
            break
    
    # 添加漏洞函数
    chain.append(f"{vuln_func}({param})")
    
    # 追踪参数来源
    param_trace = _find_parameter_source(decompile_dir, target_file, param)
    
    return {
        "call_chain": " → ".join(chain),
        "param_trace": param_trace,
    }


def _scan_vuln_by_type(export_base: str, vuln_type: str) -> list[dict]:
    patterns = {
        "command_injection": {
            "system": r"\bsystem\s*\(",
            "popen": r"\bpopen\s*\(",
            "execve": r"\bexecve\s*\(",
            "doSystemCmd": r"\bdoSystemCmd\s*\(",
        },
        "buffer_overflow": {
            "strcpy": r"\bstrcpy\s*\(",
            "sprintf": r"\bsprintf\s*\(",
            "memcpy": r"\bmemcpy\s*\(",
        },
        "format_string": {
            "printf": r"\bprintf\s*\(",
        },
        "arbitrary_file_read": {
            "fopen": r"\bfopen\s*\(",
            "open": r"\bopen\s*\(",
        },
    }
    
    severity_map = {
        "command_injection": "critical",
        "buffer_overflow": "high",
        "format_string": "high",
        "arbitrary_file_read": "medium",
    }
    
    if vuln_type not in patterns:
        return []
    
    findings = []
    vuln_patterns = patterns[vuln_type]
    
    for binary_name in sorted(os.listdir(export_base)):
        binary_dir = os.path.join(export_base, binary_name)
        if not os.path.isdir(binary_dir):
            continue
        
        decompile_dir = os.path.join(binary_dir, "decompile")
        if not os.path.exists(decompile_dir):
            continue
        
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
                
                for func_name, pattern in vuln_patterns.items():
                    if re.search(pattern, stripped, re.IGNORECASE):
                        if func_name == "system" and "zip_error" in stripped:
                            continue
                        
                        param_type = "unknown"
                        param_value = "unknown"
                        param_match = re.search(rf"{func_name}\s*\(\s*([^)]+)", stripped, re.IGNORECASE)
                        if param_match:
                            param_value = param_match.group(1).strip()
                            if param_value.startswith('"') or param_value.startswith("'"):
                                param_type = "hardcoded"
                            elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', param_value):
                                param_type = "variable"
                            else:
                                param_type = "expression"
                        
                        base_confidence = 0.95 if param_type != "hardcoded" else 0.3
                        if "int " in stripped and func_name in stripped:
                            base_confidence *= 0.5
                        
                        # 构建调用链和参数追踪
                        chain_result = _build_call_chain(
                            decompile_dir, filename, func_name, param_value
                        )
                        
                        findings.append({
                            "function": func_name,
                            "vuln_type": vuln_type,
                            "binary": binary_name,
                            "location": f"decompile/{filename}:{line_no}",
                            "file": filename,
                            "line": line_no,
                            "snippet": stripped[:200],
                            "parameter": param_value,
                            "parameter_type": param_type,
                            "call_chain": chain_result["call_chain"],
                            "param_trace": chain_result["param_trace"],
                            "severity": severity_map.get(vuln_type, "medium"),
                            "confidence": base_confidence,
                        })
    
    return findings


def _save_specialized_report(project_dir: str, binary_name: str, vuln_type: str, findings: list):
    """
    保存专用漏洞报告到 report/<binary>/<vuln-type>/ 目录
    """
    # 转换 vuln_type 为目录名
    dir_name = vuln_type.replace("_", "-")
    
    report_dir = os.path.join(project_dir, "report", binary_name, dir_name)
    os.makedirs(report_dir, exist_ok=True)
    
    # 按文件分组
    by_file = {}
    for f in findings:
        file_key = f.get("file", "unknown")
        if file_key not in by_file:
            by_file[file_key] = []
        by_file[file_key].append(f)
    
    # 保存汇总报告
    summary = {
        "binary": binary_name,
        "vuln_type": vuln_type,
        "total_findings": len(findings),
        "by_file": {k: len(v) for k, v in by_file.items()},
        "findings": findings,
    }
    
    report_path = os.path.join(report_dir, f"{vuln_type}_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
    
    # 生成 Markdown 报告 (方便阅读)
    md_path = os.path.join(report_dir, f"{vuln_type}_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# {binary_name} - {vuln_type} 漏洞报告\n\n")
        f.write(f"**发现漏洞数**: {len(findings)}\n\n")
        f.write("## 漏洞列表\n\n")
        
        for i, finding in enumerate(findings, 1):
            f.write(f"### {i}. {finding['function']}() @ {finding['location']}\n\n")
            f.write(f"- **严重程度**: {finding['severity']}\n")
            f.write(f"- **置信度**: {finding['confidence']:.2f}\n")
            f.write(f"- **调用链**: `{finding['call_chain']}`\n")
            f.write(f"- **代码片段**: `{finding['snippet'][:100]}`\n")
            f.write(f"- **参数类型**: {finding['parameter_type']}\n")
            
            # 添加参数追踪信息
            param_trace = finding.get('param_trace', {})
            if param_trace and param_trace.get('source_type') != 'unknown':
                f.write(f"- **参数来源**: {param_trace['source_type']}\n")
                if param_trace.get('source_location'):
                    f.write(f"- **来源位置**: {param_trace['source_location']}\n")
                if param_trace.get('source_code'):
                    f.write(f"- **来源代码**: `{param_trace['source_code'][:80]}`\n")
                
                # 传播链
                propagation = param_trace.get('propagation_chain', [])
                if propagation:
                    f.write(f"- **参数传播链**:\n")
                    for step in propagation:
                        if 'value' in step:
                            f.write(f"  - {step['file']}:{step.get('line', '?')}: {step['param']} = {step['value'][:50]}\n")
                        elif 'note' in step:
                            f.write(f"  - {step['file']}: {step['note']}\n")
            f.write("\n")
    
    return report_path, md_path


def create_specialized_vuln_graph(vuln_type: str):
    agent_map = {
        "command_injection": cmd_injection_agent,
        "buffer_overflow": buffer_overflow_agent,
        "format_string": format_string_agent,
        "arbitrary_file_read": file_operation_agent,
    }
    
    agent = agent_map.get(vuln_type, cmd_injection_agent)
    
    def scan_node(state: AutoSecState) -> dict:
        project = state.get("project_name", "")
        if not project:
            return {
                "messages": state["messages"] + [AIMessage(content="未提供项目名")],
                "vuln_findings": None,
            }
        
        project_dir = get_project_dir(project)
        export_base = os.path.join(project_dir, "export-for-ai")
        
        if not os.path.exists(export_base):
            return {
                "messages": state["messages"] + [AIMessage(content="未找到导出目录")],
                "vuln_findings": None,
            }
        
        print(f"[{vuln_type}] 开始扫描...")
        findings = _scan_vuln_by_type(export_base, vuln_type)
        print(f"[{vuln_type}] 发现 {len(findings)} 个候选漏洞")
        
        if not findings:
            return {
                "messages": state["messages"] + [AIMessage(content=f"未发现{vuln_type}类型漏洞")],
                "vuln_findings": [],
            }
        
        # 按二进制分组保存报告
        by_binary = {}
        for f in findings:
            binary = f["binary"]
            if binary not in by_binary:
                by_binary[binary] = []
            by_binary[binary].append(f)
        
        saved_reports = []
        for binary_name, binary_findings in by_binary.items():
            json_path, md_path = _save_specialized_report(
                project_dir, binary_name, vuln_type, binary_findings
            )
            saved_reports.append({
                "binary": binary_name,
                "count": len(binary_findings),
                "json": json_path,
                "markdown": md_path,
            })
            print(f"  [{binary_name}] 保存 {len(binary_findings)} 个漏洞到 report/{binary_name}/{vuln_type.replace('_', '-')}/")
        
        # 只传前10个给LLM分析
        findings_for_agent = findings[:10]
        
        agent_input = {
            "vuln_type": vuln_type,
            "total_findings": len(findings),
            "reports_saved": saved_reports,
            "findings": findings_for_agent,
        }
        
        summary_input = {
            "messages": [HumanMessage(content=f"漏洞扫描结果:\n{json.dumps(agent_input, indent=2, default=str)}")]
        }
        result = agent.invoke(summary_input)
        
        # 添加报告路径信息到输出
        report_info = "\n\n📁 **报告已保存**:\n"
        for r in saved_reports:
            report_info += f"- `{r['binary']}`: {r['count']} 个漏洞 → `report/{r['binary']}/{vuln_type.replace('_', '-')}/`\n"
        
        final_content = result["messages"][-1].content + report_info
        result["messages"][-1] = AIMessage(content=final_content)
        
        return {
            "messages": result["messages"],
            "vuln_findings": findings,
        }
    
    builder = StateGraph(AutoSecState)
    builder.add_node("scan", scan_node)
    builder.set_entry_point("scan")
    builder.add_edge("scan", END)
    
    return builder.compile()


cmd_injection_graph = create_specialized_vuln_graph("command_injection")
buffer_overflow_graph = create_specialized_vuln_graph("buffer_overflow")
format_string_graph = create_specialized_vuln_graph("format_string")
file_operation_graph = create_specialized_vuln_graph("arbitrary_file_read")
