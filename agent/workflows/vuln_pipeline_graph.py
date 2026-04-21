"""
漏洞分析流水线工作流

四个专用 Agent 形成流水线：
1. recon_agent (信息侦查) → 
2. cmd_inject_agent (命令注入高危函数侦查) → 
3. xrefs_agent (漏洞疑点交叉引用关系梳理) → 
4. verify_agent (漏洞验证)

共享 state 传递分析结果
"""

import json
import os
import re
from typing import Any

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.path_guard import get_project_dir
from core.state import AutoSecState
from tools.vuln.rag_engine import VulnRAG
from tools.vuln.xref_tools import read_decompiled_function, lookup_function_xrefs

# ============== 系统提示词定义 ==============

RECON_AGENT_PROMPT = """
你是信息侦查 Agent，负责收集目标固件的基础情报。

## 任务
1. 探测网络拓扑相关信息（通信协议、端口、服务发现）
2. 收集硬件信息（芯片型号、架构、外设接口）
3. 搜索硬编码敏感信息（密码、密钥、Token、API Key）
4. 收集密钥证书（PEM/DER/Key 文件）

## 输出格式
请返回结构化的侦查结果：
{
  "network_info": {
    "protocols": ["MQTT", "TLS", "SOME/IP"],
    "ports": [1883, 8883],
    "services": ["broker", "telematics"]
  },
  "hardware_info": {
    "chip": "Qualcomm SA8155",
    "architecture": "ARM64",
    "peripherals": ["CAN", "Ethernet", "4G"]
  },
  "hardcoded_secrets": [
    {"type": "password", "location": "file.c:123", "context": "admin_password = \"xxx\""}
  ],
  "certificates": [
    {"type": "RSA_private_key", "location": "file.pem", "size": 2048}
  ],
  "summary": "侦查摘要..."
}
"""

CMD_INJECT_RECON_PROMPT = """
你是高危函数侦查 Agent，专注于发现各类危险函数调用。

## 侦查目标
1. 命令注入函数：
   - system(), popen(), popenve()
   - execve(), execv(), execvp(), execl(), execlp()
   - eval(), assert()

2. 缓冲区溢出函数：
   - strcpy(), strcat(), sprintf()
   - gets(), scanf()

3. 格式化字符串函数：
   - printf(), fprintf(), sprintf(), snprintf()

4. 文件操作函数：
   - fopen(), open(), fread(), fwrite()

## 输出格式
{
  "findings": [
    {
      "function": "system",
      "vuln_type": "command_injection",
      "location": "decompile/abc.c:45",
      "line": 45,
      "snippet": "system(v8);",
      "parameter_type": "variable",
      "parameter_name": "v8",
      "severity": "critical",
      "confidence": 0.95
    }
  ],
  "statistics": {
    "total_findings": 10,
    "system_count": 5,
    "popen_count": 3,
    "exec_count": 2
  }
}
"""

XREFS_ANALYSIS_PROMPT = """
你是漏洞疑点交叉引用关系梳理 Agent，负责追踪高危函数的参数来源和调用链。

你有两个工具可以使用：
1. **lookup_function_xrefs**: 查询函数的调用者(callers)和被调用者(callees)
2. **read_decompiled_function**: 读取函数的反编译源码

## 工作流程

对于每个高危函数发现：

1. **读取漏洞所在函数的源码**：用 read_decompiled_function 读取包含危险调用的函数
2. **分析参数来源**：在代码中找到危险函数的参数（如 system(v8) 中的 v8），追踪它在当前函数中的赋值和来源
3. **向上追踪调用者**：用 lookup_function_xrefs 查看谁调用了当前函数，然后用 read_decompiled_function 读取调用者的代码，看参数是如何传入的
4. **重复追踪**：继续向上追踪 2-3 层，直到找到数据的最终来源（用户输入/网络数据/硬编码值）
5. **判断可控性**：根据完整的数据流判断参数是否用户可控

## 关键判断标准
- 参数来自 recv/socket/read/fgets/getenv/argv/CGI参数 → 用户可控，高危
- 参数来自硬编码字符串常量 → 不可控，通常是误报
- 参数来自函数参数且该函数被外部调用 → 需要继续向上追踪
- 参数经过 strncpy 限长、白名单过滤、输入校验 → 已净化，风险降低

## 输出格式
{
  "analysis": [
    {
      "original_finding": { /* 原始发现 */ },
      "call_chain": [
        {"function": "main", "file": "20F8.c", "action": "调用 setDiagnoShellPath(user_path)"},
        {"function": "setDiagnoShellPath", "file": "7928.c", "action": "strncpy 到全局变量 byte_F674"},
        {"function": "ThreadNetworkDiagno", "file": "3068.c", "action": "popen(v8)，v8 来自 byte_F674"}
      ],
      "data_flow": {
        "source": "函数参数（外部可控）",
        "intermediate_vars": ["a1", "byte_F674", "v8"],
        "sanitization": "strncpy 限长 0x7F 字节，但无命令字符过滤",
        "sink": "popen()"
      },
      "is_controllable": true,
      "confidence": 0.9,
      "reasoning": "参数经 setDiagnoShellPath 的参数传入，通过全局变量传递到 popen，仅有长度限制无命令注入过滤"
    }
  ]
}
"""

VERIFICATION_PROMPT = """
你是漏洞验证 Agent，负责验证漏洞的真实性并构造验证Payload。

你有两个工具可以使用：
1. **lookup_function_xrefs**: 查询函数的调用者(callers)和被调用者(callees)
2. **read_decompiled_function**: 读取函数的反编译源码

## 工作流程

对于每个待验证的漏洞：

1. **读取漏洞代码**：用 read_decompiled_function 读取漏洞所在函数，确认漏洞存在
2. **复核调用链**：如果对上游分析有疑问，可以自己用工具追踪确认
3. **评估利用条件**：
   - 参数可控性是否已确认
   - 是否需要认证、特定状态等前置条件
   - 利用难度和影响范围
4. **构造验证 Payload**（对确认可利用的漏洞）
5. **给出 CVSS 评分和修复建议**

## 输出格式
{
  "verification": [
    {
      "vulnerability_id": "VULN-001",
      "type": "command_injection",
      "status": "confirmed",
      "cvss_score": 9.8,
      "severity": "critical",

      "exploitability": {
        "prerequisites": ["网络可达", "无需认证"],
        "attack_vector": "网络",
        "complexity": "低",
        "privileges_required": "无"
      },

      "payload": {
        "type": "network_packet",
        "description": "构造包含命令注入的诊断路径",
        "example": "; /bin/sh -c 'id'; #"
      },

      "impact": {
        "confidentiality": "完全泄露",
        "integrity": "完全破坏",
        "availability": "完全破坏"
      },

      "remediation": {
        "immediate": "禁止直接使用 popen/system 执行用户输入",
        "short_term": "使用 execve 并严格限制参数",
        "long_term": "实现命令白名单机制"
      }
    }
  ],
  "summary": "验证完成，确认X个漏洞可利用..."
}
"""

# ============== 创建 Agents ==============

xref_tools = [read_decompiled_function, lookup_function_xrefs]

recon_agent = create_agent(model, tools=[], system_prompt=RECON_AGENT_PROMPT)
cmd_inject_recon_agent = create_agent(model, tools=[], system_prompt=CMD_INJECT_RECON_PROMPT)
xrefs_agent = create_agent(model, tools=xref_tools, system_prompt=XREFS_ANALYSIS_PROMPT)
verify_agent = create_agent(model, tools=xref_tools, system_prompt=VERIFICATION_PROMPT)


# ============== 工具函数 ==============

def _scan_vulnerable_functions(export_base: str) -> list[dict]:
    """
    扫描各类高危函数（命令注入、缓冲区溢出、格式化字符串、文件操作等）
    """
    # 定义各类漏洞的模式
    vuln_patterns = {
        "command_injection": {
            "patterns": {
                "system": r"\bsystem\s*\(",
                "popen": r"\bpopen\s*\(",
                "popenve": r"\bpopenve\s*\(",
                "execve": r"\bexecve\s*\(",
                "execv": r"\bexecv\s*\(",
                "execvp": r"\bexecvp\s*\(",
                "execl": r"\bexecl\s*\(",
                "execlp": r"\bexeclp\s*\(",
                "eval": r"\beval\s*\(",
            },
            "severity": "critical",
        },
        "buffer_overflow": {
            "patterns": {
                "strcpy": r"\bstrcpy\s*\(",
                "strcat": r"\bstrcat\s*\(",
                "sprintf": r"\bsprintf\s*\(",
                "gets": r"\bgets\s*\(",
                "memcpy_unsafe": r"\bmemcpy\s*\(",
            },
            "severity": "high",
        },
        "format_string": {
            "patterns": {
                "printf": r"\bprintf\s*\(",
                "fprintf": r"\bfprintf\s*\(",
                "sprintf_fmt": r"\bsprintf\s*\(",
            },
            "severity": "high",
        },
        "arbitrary_file_read": {
            "patterns": {
                "fopen": r"\bfopen\s*\(",
                "open": r"\bopen\s*\(",
                "access": r"\baccess\s*\(",
            },
            "severity": "medium",
        },
    }
    
    findings = []
    
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
                
                # 检查每种类型的漏洞
                for vuln_type, vuln_info in vuln_patterns.items():
                    for func_name, pattern in vuln_info["patterns"].items():
                        if re.search(pattern, stripped, re.IGNORECASE):
                            # 过滤误报：zip_error_code_system 等不是 system()
                            if func_name == "system" and "zip_error" in stripped:
                                continue
                            if func_name == "open" and re.search(r"\b(zip_|error_)", stripped):
                                continue
                            
                            # 分析参数类型
                            param_type = "unknown"
                            param_match = re.search(rf"{func_name}\s*\(\s*([^)]+)", stripped, re.IGNORECASE)
                            if param_match:
                                param = param_match.group(1).strip()
                                if param.startswith('"') or param.startswith("'"):
                                    param_type = "hardcoded"
                                elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', param):
                                    param_type = "variable"
                                else:
                                    param_type = "expression"
                            
                            # 计算置信度
                            base_confidence = 0.95 if param_type != "hardcoded" else 0.3
                            # 函数声明行（如 "int printf(..."）置信度较低
                            if "int " in stripped and func_name in stripped:
                                base_confidence *= 0.5
                            
                            findings.append({
                                "function": func_name,
                                "vuln_type": vuln_type,
                                "binary": binary_name,
                                "location": f"decompile/{filename}:{line_no}",
                                "file": f"decompile/{filename}",
                                "line": line_no,
                                "snippet": stripped[:200],
                                "parameter": param_match.group(1) if param_match else "unknown",
                                "parameter_type": param_type,
                                "severity": vuln_info["severity"] if param_type != "hardcoded" else "low",
                                "confidence": base_confidence,
                            })
    
    return findings


def _collect_network_info(export_base: str) -> dict:
    """收集网络相关信息"""
    protocols = set()
    keywords = {
        "MQTT": ["mqtt", "mosquitto", "publish", "subscribe"],
        "TLS/SSL": ["tls", "ssl", "openssl", "certificate"],
        "HTTP": ["http", "curl", "wget"],
        "SOME/IP": ["someip", "some/ip", "sd_"],
        "CAN": ["can_socket", "can_frame", "can_bus"],
        "DDS": ["dds", "fastdds", "rtps"],
    }
    
    for binary_name in os.listdir(export_base):
        binary_dir = os.path.join(export_base, binary_name)
        if not os.path.isdir(binary_dir):
            continue
            
        strings_path = os.path.join(binary_dir, "strings.txt")
        if os.path.exists(strings_path):
            try:
                with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    for proto, keys in keywords.items():
                        if any(k in content for k in keys):
                            protocols.add(proto)
            except:
                pass
    
    return {
        "protocols": list(protocols),
        "keywords_found": list(protocols)
    }


def _collect_hardcoded_secrets(export_base: str) -> list[dict]:
    """收集硬编码敏感信息"""
    secrets = []
    secret_patterns = [
        (r"password\s*=\s*['\"]([^'\"]+)", "password"),
        (r"passwd\s*=\s*['\"]([^'\"]+)", "password"),
        (r"secret\s*=\s*['\"]([^'\"]+)", "secret"),
        (r"api_key\s*=\s*['\"]([^'\"]+)", "api_key"),
        (r"token\s*=\s*['\"]([^'\"]+)", "token"),
        (r"private_key\s*=\s*['\"]([^'\"]+)", "private_key"),
    ]
    
    for binary_name in os.listdir(export_base):
        binary_dir = os.path.join(export_base, binary_name)
        if not os.path.isdir(binary_dir):
            continue
            
        strings_path = os.path.join(binary_dir, "strings.txt")
        if os.path.exists(strings_path):
            try:
                with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_no, line in enumerate(f, 1):
                        for pattern, secret_type in secret_patterns:
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                secrets.append({
                                    "type": secret_type,
                                    "binary": binary_name,
                                    "location": f"strings.txt:{line_no}",
                                    "context": line.strip()[:100],
                                    "value_hint": match.group(1)[:20] if match.groups() else ""
                                })
            except:
                pass
    
    return secrets


# ============== 节点函数 ==============

def recon_node(state: AutoSecState) -> dict:
    """
    Agent 1: 信息侦查
    收集网络拓扑、硬件信息、硬编码、密钥证书
    """
    print(f"[Recon] 开始信息侦查...")
    project = state.get("project_name", "")
    if not project:
        print(f"[Recon] 跳过: project_name 为空")
        return {
            "messages": state["messages"] + [AIMessage(content="未提供项目名")],
            "recon_data": None,
        }

    project_dir = get_project_dir(project)
    export_base = os.path.join(project_dir, "export-for-ai")

    if not os.path.exists(export_base):
        print(f"[Recon] 跳过: 导出目录不存在 {export_base}")
        return {
            "messages": state["messages"] + [AIMessage(content=f"未找到导出目录: {export_base}")],
            "recon_data": None,
        }
    
    # 收集信息
    network_info = _collect_network_info(export_base)
    secrets = _collect_hardcoded_secrets(export_base)
    
    # 收集证书信息
    certs = []
    cert_patterns = [
        (rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", "X509_CERT"),
        (rb"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----", "RSA_PRIVATE_KEY"),
        (rb"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", "PRIVATE_KEY"),
    ]
    
    for binary_name in os.listdir(export_base):
        binary_dir = os.path.join(export_base, binary_name)
        if not os.path.isdir(binary_dir):
            continue
        
        # 检查 memory 目录
        memory_dir = os.path.join(binary_dir, "memory")
        if os.path.exists(memory_dir):
            for mem_file in os.listdir(memory_dir):
                mem_path = os.path.join(memory_dir, mem_file)
                try:
                    with open(mem_path, "rb") as f:
                        content = f.read()
                        for pattern, cert_type in cert_patterns:
                            matches = re.findall(pattern, content, re.DOTALL)
                            for match in matches:
                                certs.append({
                                    "type": cert_type,
                                    "binary": binary_name,
                                    "source": mem_file,
                                    "size": len(match)
                                })
                except:
                    pass
    
    recon_data = {
        "network_info": network_info,
        "hardcoded_secrets": secrets,
        "certificates": certs,
        "scanned_binaries": [d for d in os.listdir(export_base) if os.path.isdir(os.path.join(export_base, d))],
    }
    
    print(f"[Recon] 完成: 发现 {len(secrets)} 个硬编码秘密, {len(certs)} 个证书")

    # 使用 Agent 生成摘要
    summary_input = {
        "messages": [HumanMessage(content=f"侦查结果:\n{json.dumps(recon_data, indent=2, default=str)}")]
    }
    try:
        result = recon_agent.invoke(summary_input)
        agent_messages = result["messages"]
    except Exception as e:
        print(f"[Recon] Agent 摘要生成出错: {e}")
        agent_messages = [AIMessage(content=f"信息侦查完成（Agent 摘要生成失败: {e}）")]

    return {
        "messages": state["messages"] + agent_messages,
        "recon_data": recon_data,
    }


def cmd_inject_recon_node(state: AutoSecState) -> dict:
    """
    Agent 2: 命令注入高危函数侦查
    专门侦查 system(), popen(), exec() 等高危函数
    """
    print(f"[VulnRecon] 进入高危函数侦查节点...")
    project = state.get("project_name", "")
    if not project:
        print(f"[VulnRecon] 跳过: project_name 为空")
        return {
            "messages": state["messages"] + [AIMessage(content="未提供项目名")],
            "cmd_inject_findings": None,
        }

    project_dir = get_project_dir(project)
    export_base = os.path.join(project_dir, "export-for-ai")

    if not os.path.exists(export_base):
        print(f"[VulnRecon] 跳过: 导出目录不存在 {export_base}")
        return {
            "messages": state["messages"] + [AIMessage(content=f"未找到导出目录: {export_base}")],
            "cmd_inject_findings": None,
        }
    
    # 扫描高危函数
    print(f"[VulnRecon] 开始扫描高危函数...")
    findings = _scan_vulnerable_functions(export_base)
    print(f"[VulnRecon] 发现 {len(findings)} 个高危函数调用")
    
    # 显示部分发现
    for i, f in enumerate(findings[:3]):
        print(f"  [{i+1}] {f['function']}() at {f['location']} (param: {f['parameter_type']}, conf: {f['confidence']})")
    if len(findings) > 3:
        print(f"  ... 还有 {len(findings)-3} 个")
    
    # 统计
    stats = {
        "total_findings": len(findings),
        "by_type": {
            "command_injection": len([f for f in findings if f.get("vuln_type") == "command_injection"]),
            "buffer_overflow": len([f for f in findings if f.get("vuln_type") == "buffer_overflow"]),
            "format_string": len([f for f in findings if f.get("vuln_type") == "format_string"]),
            "arbitrary_file_read": len([f for f in findings if f.get("vuln_type") == "arbitrary_file_read"]),
        },
        "high_confidence": len([f for f in findings if f["confidence"] > 0.8]),
    }
    
    # 限制传给 LLM 的数据量 - 每类漏洞选最高置信度的几个，确保多样性
    selected_findings = []
    
    # 优先选择命令注入（最关键）
    cmd_inject_findings = [f for f in findings if f["vuln_type"] == "command_injection" and f["confidence"] > 0.8]
    for f in cmd_inject_findings[:3]:
        selected_findings.append({
            "function": f["function"],
            "vuln_type": f["vuln_type"],
            "location": f["location"],
            "parameter_type": f["parameter_type"],
            "confidence": f["confidence"],
            "snippet": f["snippet"][:100],
        })
    
    # 其他类型各选几个
    for vuln_type in ["buffer_overflow", "format_string", "arbitrary_file_read"]:
        type_findings = [f for f in findings if f["vuln_type"] == vuln_type and f["confidence"] > 0.8]
        for f in type_findings[:2]:
            selected_findings.append({
                "function": f["function"],
                "vuln_type": f["vuln_type"],
                "location": f["location"],
                "parameter_type": f["parameter_type"],
                "confidence": f["confidence"],
                "snippet": f["snippet"][:100],
            })
        if len(selected_findings) >= 10:
            break
    
    cmd_inject_data = {
        "findings": findings,  # 保留完整数据给后续节点
        "statistics": stats,
    }
    
    # 使用 Agent 分析（只传精简数据）
    agent_input = {
        "statistics": stats,
        "selected_findings": selected_findings,
        "note": f"共发现 {len(findings)} 个高危函数，这里精选了 {len(selected_findings)} 个高置信度且类型多样的发现"
    }
    
    summary_input = {
        "messages": [HumanMessage(content=f"高危函数侦查结果:\n{json.dumps(agent_input, indent=2, default=str)}")]
    }
    try:
        result = cmd_inject_recon_agent.invoke(summary_input)
        agent_messages = result["messages"]
    except Exception as e:
        print(f"[VulnRecon] Agent 分析出错: {e}")
        agent_messages = [AIMessage(content=f"高危函数扫描完成（Agent 分析失败: {e}）")]

    return {
        "messages": state["messages"] + agent_messages,
        "cmd_inject_findings": cmd_inject_data,
    }


def xrefs_analysis_node(state: AutoSecState) -> dict:
    """
    Agent 3: 漏洞疑点交叉引用关系梳理
    让 Agent 用工具自主追踪参数来源和调用链
    """
    print(f"[XrefsAnalysis] 开始交叉引用分析...")
    vuln_recon_data = state.get("cmd_inject_findings")

    if not vuln_recon_data or not vuln_recon_data.get("findings"):
        print(f"[XrefsAnalysis] 跳过: cmd_inject_findings 为空 (vuln_recon_data={type(vuln_recon_data).__name__})")
        return {
            "messages": state["messages"] + [AIMessage(content="没有高危函数发现可供分析")],
            "xrefs_analysis": None,
        }

    project = state.get("project_name", "")

    all_findings = vuln_recon_data.get("findings", [])
    # 筛选高置信度、非硬编码的发现
    actionable = [
        f for f in all_findings
        if f.get("confidence", 0) > 0.5 and f.get("parameter_type") != "hardcoded"
    ]
    # 按置信度排序，取 top 20
    actionable.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    findings_to_analyze = actionable[:20]

    print(f"[XrefsAnalysis] 筛选出 {len(findings_to_analyze)} 个待分析发现 (从 {len(all_findings)} 个中)")

    if not findings_to_analyze:
        return {
            "messages": state["messages"] + [AIMessage(content="没有高置信度的非硬编码发现需要分析")],
            "xrefs_analysis": {"analysis": [], "total_analyzed": 0, "controllable_count": 0},
        }

    all_analysis_results = []

    for i, finding in enumerate(findings_to_analyze):
        print(f"[XrefsAnalysis] 分析 {i+1}/{len(findings_to_analyze)}: {finding['function']}() @ {finding['location']}")

        # 构建 Agent 输入
        task = {
            "project_name": project,
            "binary_name": finding["binary"],
            "vuln_type": finding.get("vuln_type", "unknown"),
            "function": finding["function"],
            "location": finding["location"],
            "file": finding.get("file", ""),
            "line": finding.get("line", 0),
            "snippet": finding.get("snippet", "")[:200],
            "parameter": finding.get("parameter", "unknown"),
            "parameter_type": finding.get("parameter_type", "unknown"),
        }

        prompt = (
            f"请分析以下高危函数调用的参数来源和调用链。\n\n"
            f"项目名: {task['project_name']}\n"
            f"二进制: {task['binary_name']}\n"
            f"漏洞类型: {task['vuln_type']}\n"
            f"危险函数: {task['function']}()\n"
            f"位置: {task['location']}\n"
            f"代码片段: {task['snippet']}\n"
            f"参数: {task['parameter']}\n\n"
            f"请使用工具追踪这个参数的来源：\n"
            f"1. 先用 read_decompiled_function 读取 {task['file'].replace('decompile/', '')} 查看完整代码\n"
            f"2. 用 lookup_function_xrefs 查看调用者\n"
            f"3. 逐级向上追踪参数来源\n"
            f"4. 判断参数是否用户可控"
        )

        try:
            result = xrefs_agent.invoke({
                "messages": [HumanMessage(content=prompt)]
            })

            agent_response = result["messages"][-1].content

            # 尝试从 Agent 响应中提取结构化数据
            analysis_entry = {
                "original_finding": finding,
                "agent_analysis": agent_response,
                "is_controllable": _extract_controllability(agent_response),
                "confidence": finding.get("confidence", 0.5),
            }
            all_analysis_results.append(analysis_entry)

        except Exception as e:
            print(f"[XrefsAnalysis] Agent 分析出错: {e}")
            all_analysis_results.append({
                "original_finding": finding,
                "agent_analysis": f"分析失败: {str(e)}",
                "is_controllable": finding.get("parameter_type") == "variable",
                "confidence": 0.3,
            })

    xrefs_data = {
        "analysis": all_analysis_results,
        "total_analyzed": len(all_analysis_results),
        "controllable_count": len([a for a in all_analysis_results if a.get("is_controllable", False)]),
    }

    print(f"[XrefsAnalysis] 完成: 分析 {xrefs_data['total_analyzed']} 个，{xrefs_data['controllable_count']} 个判定为可控")

    # 生成汇总消息
    summary_lines = [
        f"交叉引用分析完成：共分析 {xrefs_data['total_analyzed']} 个高危发现，"
        f"{xrefs_data['controllable_count']} 个参数判定为可控。",
        "",
    ]
    for a in all_analysis_results[:5]:
        finding = a["original_finding"]
        ctrl = "可控" if a.get("is_controllable") else "不可控/未知"
        summary_lines.append(f"- {finding['function']}() @ {finding['location']} → {ctrl}")

    if len(all_analysis_results) > 5:
        summary_lines.append(f"... 还有 {len(all_analysis_results) - 5} 个")

    return {
        "messages": state["messages"] + [AIMessage(content="\n".join(summary_lines))],
        "xrefs_analysis": xrefs_data,
    }


def _extract_controllability(agent_response: str) -> bool:
    """从 Agent 的文本响应中提取可控性判断"""
    response_lower = agent_response.lower()
    positive_signals = ["is_controllable\": true", "可控", "user_input", "用户可控", "外部可控", "confirmed"]
    negative_signals = ["is_controllable\": false", "不可控", "hardcoded", "硬编码", "false_positive", "误报"]

    pos_score = sum(1 for s in positive_signals if s in response_lower)
    neg_score = sum(1 for s in negative_signals if s in response_lower)

    return pos_score > neg_score


def verify_node(state: AutoSecState) -> dict:
    """
    Agent 4: 漏洞验证
    让 Agent 用工具自主读取代码，验证漏洞真实性并构造 Payload
    """
    print(f"[Verify] 开始漏洞验证...")
    xrefs_data = state.get("xrefs_analysis")

    if not xrefs_data or not isinstance(xrefs_data.get("analysis"), list) or len(xrefs_data.get("analysis", [])) == 0:
        print(f"[Verify] 跳过: 没有交叉引用分析结果 (xrefs_data type={type(xrefs_data).__name__}, "
              f"analysis={type(xrefs_data.get('analysis')).__name__ if xrefs_data else 'N/A'})")
        return {
            "messages": state["messages"] + [AIMessage(content="没有交叉引用分析结果可供验证")],
            "verification_results": None,
        }

    project = state.get("project_name", "")
    analysis_results = xrefs_data["analysis"]

    # 只验证判定为可控的发现
    controllable = [a for a in analysis_results if a.get("is_controllable", False)]
    if not controllable:
        controllable = analysis_results[:5]
    controllable = controllable[:10]

    print(f"[Verify] 待验证 {len(controllable)} 个发现")

    # 把所有待验证发现打包成一次 Agent 调用
    findings_summary = []
    for i, analysis in enumerate(controllable):
        finding = analysis["original_finding"]
        findings_summary.append({
            "index": i + 1,
            "binary": finding.get("binary", ""),
            "function": finding.get("function", ""),
            "vuln_type": finding.get("vuln_type", ""),
            "location": finding.get("location", ""),
            "snippet": finding.get("snippet", "")[:150],
            "parameter": finding.get("parameter", ""),
            "agent_analysis_excerpt": str(analysis.get("agent_analysis", ""))[:300],
        })

    prompt = (
        f"以下是经过交叉引用分析后判定为参数可控的 {len(findings_summary)} 个漏洞发现。\n"
        f"项目名: {project}\n\n"
        f"请逐个验证这些漏洞，你可以使用工具读取代码来确认。\n"
        f"对每个漏洞给出：status（confirmed/needs_manual_review）、CVSS评分、Payload、修复建议。\n\n"
        f"待验证漏洞列表:\n{json.dumps(findings_summary, ensure_ascii=False, indent=2)}"
    )

    try:
        result = verify_agent.invoke({
            "messages": [HumanMessage(content=prompt)]
        })
        agent_response = result["messages"][-1].content
    except Exception as e:
        print(f"[Verify] Agent 验证出错: {e}")
        agent_response = f"验证过程出错: {str(e)}"

    # 构建验证结果
    verifications = []
    for analysis in controllable:
        finding = analysis["original_finding"]
        verifications.append({
            "vulnerability_id": f"VULN-{finding.get('binary', 'UNK')}-{finding.get('line', 0)}",
            "type": finding.get("vuln_type", "unknown"),
            "function": finding.get("function", ""),
            "location": finding.get("location", ""),
            "snippet": finding.get("snippet", "")[:200],
            "is_controllable": analysis.get("is_controllable", False),
        })

    verification_data = {
        "verification": verifications,
        "agent_report": agent_response,
        "summary": {
            "total": len(verifications),
            "analyzed": len(controllable),
        },
    }

    # 保存验证报告
    project_dir = get_project_dir(project)
    report_dir = os.path.join(project_dir, "report")
    os.makedirs(report_dir, exist_ok=True)

    report_path = os.path.join(report_dir, "vuln_verification_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(verification_data, f, ensure_ascii=False, indent=2, default=str)

    final_content = agent_response + f"\n\n📁 验证报告已保存: {report_path}"

    return {
        "messages": state["messages"] + [AIMessage(content=final_content)],
        "verification_results": verification_data,
        "vuln_findings": verifications,
    }


# ============== 构建流水线工作流 ==============

builder = StateGraph(AutoSecState)

# 添加四个节点
builder.add_node("recon_agent", recon_node)
builder.add_node("cmd_inject_recon", cmd_inject_recon_node)
builder.add_node("xrefs_analysis", xrefs_analysis_node)
builder.add_node("verify_agent", verify_node)

# 设置入口和流水线边
builder.set_entry_point("recon_agent")
builder.add_edge("recon_agent", "cmd_inject_recon")
builder.add_edge("cmd_inject_recon", "xrefs_analysis")
builder.add_edge("xrefs_analysis", "verify_agent")
builder.add_edge("verify_agent", END)

vuln_pipeline_graph = builder.compile()
