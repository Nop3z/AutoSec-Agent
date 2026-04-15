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

## 支持的漏洞类型
- command_injection: 命令注入 (system, popen, exec等)
- buffer_overflow: 缓冲区溢出 (strcpy, strcat, sprintf等)
- format_string: 格式化字符串 (printf, fprintf等)
- arbitrary_file_read: 任意文件读取 (fopen, open等)
- hardcoded_credential: 硬编码凭证
- insecure_crypto: 不安全加密

## 任务
1. 接收高危函数侦查 Agent 的发现
2. 分析反汇编/反编译文件，追踪参数的数据流：
   - 参数是否为硬编码字符串（通常是误报）
   - 参数是否来自用户输入（网络、文件、环境变量）
   - 参数是否经过中间函数处理/转换
   - 参数传递的完整调用链

3. 构造完整的函数调用链和传参链

## 分析方法
- 查看函数的交叉引用（Xrefs）
- 追踪变量的定义和使用（Def-Use链）
- 识别数据来源（socket接收、文件读取、命令行参数等）
- 标记净化处理（长度检查、白名单过滤等）

## 输出格式
{
  "analysis": [
    {
      "original_finding": { /* 原始发现 */ },
      "call_chain": [
        {"function": "main", "location": "main.c:100", "action": "接收网络数据到buffer"},
        {"function": "process_data", "location": "utils.c:50", "action": "复制到v8，无过滤"},
        {"function": "execute_cmd", "location": "cmd.c:20", "action": "调用system(v8)"}
      ],
      "data_flow": {
        "source": "网络socket接收",
        "intermediate_vars": ["buffer", "v8"],
        "sanitization": "none",
        "sink": "system()"
      },
      "is_controllable": true,
      "confidence": 0.9,
      "reasoning": "参数v8直接来源于网络数据，无过滤直接传入system"
    }
  ]
}
"""

VERIFICATION_PROMPT = """
你是漏洞验证 Agent，负责验证漏洞的真实性并构造验证Payload。

## 支持的漏洞类型
- command_injection: 命令注入 (system, popen, exec等)
- buffer_overflow: 缓冲区溢出 (strcpy, strcat, sprintf等)
- format_string: 格式化字符串 (printf, fprintf等)
- arbitrary_file_read: 任意文件读取 (fopen, open等)
- hardcoded_credential: 硬编码凭证
- insecure_crypto: 不安全加密

## 任务
1. 接收来自交叉引用分析 Agent 的调用链信息
2. 验证漏洞是否真实可利用：
   - 确认参数可控性
   - 分析利用条件（是否需要认证、特定状态等）
   - 评估利用难度和影响范围

3. 构造验证 Payload（如果可以）：
   - 网络数据包格式
   - 文件内容构造
   - 命令注入字符串
   - 格式化字符串攻击串
   - 缓冲区溢出攻击串
   - 目录遍历路径

4. 给出 CVSS 评分和修复建议

## 输出格式
{
  "verification": [
    {
      "vulnerability_id": "VULN-001",
      "type": "command_injection",  // 或 format_string, buffer_overflow等
      "status": "confirmed",  // confirmed / unconfirmed / needs_manual_review
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
        "description": "构造包含命令注入的MQTT消息",
        "raw_bytes": "...",
        "example": "'; /bin/sh -c 'id'; '"
      },
      
      "impact": {
        "confidentiality": "完全泄露",
        "integrity": "完全破坏", 
        "availability": "完全破坏"
      },
      
      "remediation": {
        "immediate": "禁止直接使用system()执行用户输入",
        "short_term": "使用execve()并严格限制参数",
        "long_term": "实现命令白名单机制"
      }
    }
  ],
  "summary": "验证完成，确认X个漏洞可利用..."
}
"""

# ============== 创建 Agents ==============

recon_agent = create_agent(model, tools=[], system_prompt=RECON_AGENT_PROMPT)
cmd_inject_recon_agent = create_agent(model, tools=[], system_prompt=CMD_INJECT_RECON_PROMPT)
xrefs_agent = create_agent(model, tools=[], system_prompt=XREFS_ANALYSIS_PROMPT)
verify_agent = create_agent(model, tools=[], system_prompt=VERIFICATION_PROMPT)


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
        return {
            "messages": state["messages"] + [AIMessage(content="未提供项目名")],
            "recon_data": None,
        }
    
    project_dir = get_project_dir(project)
    export_base = os.path.join(project_dir, "export-for-ai")
    
    if not os.path.exists(export_base):
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
    result = recon_agent.invoke(summary_input)
    
    return {
        "messages": result["messages"],
        "recon_data": recon_data,
    }


def cmd_inject_recon_node(state: AutoSecState) -> dict:
    """
    Agent 2: 命令注入高危函数侦查
    专门侦查 system(), popen(), exec() 等高危函数
    """
    project = state.get("project_name", "")
    if not project:
        return {
            "messages": state["messages"] + [AIMessage(content="未提供项目名")],
            "cmd_inject_findings": None,
        }
    
    project_dir = get_project_dir(project)
    export_base = os.path.join(project_dir, "export-for-ai")
    
    if not os.path.exists(export_base):
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
    result = cmd_inject_recon_agent.invoke(summary_input)
    
    return {
        "messages": result["messages"],
        "cmd_inject_findings": cmd_inject_data,
    }


def xrefs_analysis_node(state: AutoSecState) -> dict:
    """
    Agent 3: 漏洞疑点交叉引用关系梳理
    接收高危函数侦查结果，追踪参数来源，构造调用链
    """
    vuln_recon_data = state.get("cmd_inject_findings")
    
    if not vuln_recon_data or not vuln_recon_data.get("findings"):
        return {
            "messages": state["messages"] + [AIMessage(content="没有高危函数发现可供分析")],
            "xrefs_analysis": None,
        }
    
    project = state.get("project_name", "")
    project_dir = get_project_dir(project)
    export_base = os.path.join(project_dir, "export-for-ai")
    
    # 对每个高危发现进行交叉引用分析（限制最多分析100个，避免超时）
    all_findings = vuln_recon_data.get("findings", [])
    # 优先分析高置信度的发现
    sorted_findings = sorted(all_findings, key=lambda x: x.get("confidence", 0), reverse=True)
    findings_to_analyze = sorted_findings[:100]
    print(f"[XrefsAnalysis] 开始分析 {len(findings_to_analyze)} 个发现 (从 {len(all_findings)} 个中筛选)...")
    analysis_results = []
    
    for finding in findings_to_analyze:
        # 分析所有非硬编码的发现（降低阈值）
        if finding["confidence"] < 0.3:
            continue
        
        # 获取函数索引信息（如果存在）
        func_index_path = os.path.join(
            export_base, finding["binary"], "function_index.txt"
        )
        
        call_chain = []
        
        # 尝试从函数索引中查找交叉引用
        if os.path.exists(func_index_path):
            try:
                with open(func_index_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # 查找当前函数的调用者
                    func_name = finding["location"].split("/")[-1].split(":")[0].replace(".c", "")
                    # 简单的模式匹配查找调用关系
                    for line in content.split("\n")[:50]:  # 限制行数
                        if func_name in line and "call" in line.lower():
                            call_chain.append({"info": line.strip()})
            except:
                pass
        
        # 判断参数可控性
        is_controllable = finding["parameter_type"] == "variable"
        
        analysis = {
            "original_finding": finding,
            "call_chain": call_chain if call_chain else [{"info": "需要手动分析调用链"}],
            "data_flow": {
                "source": "unknown" if finding["parameter_type"] == "variable" else "hardcoded",
                "parameter": finding["parameter"],
                "parameter_type": finding["parameter_type"],
                "sink": finding["function"] + "()"
            },
            "is_controllable": is_controllable,
            "confidence": finding["confidence"] * (0.9 if is_controllable else 0.5),
            "reasoning": f"参数类型为{finding['parameter_type']}，" + 
                        ("可能来自外部输入" if is_controllable else "硬编码值，误报可能性高")
        }
        
        analysis_results.append(analysis)
    
    # 如果没有分析结果，创建一个默认的
    if not analysis_results:
        print(f"[XrefsAnalysis] 警告: 没有通过置信度过滤的发现，尝试分析低置信度样本...")
        # 尝试分析所有发现，即使置信度较低
        for finding in vuln_recon_data["findings"][:5]:  # 最多分析前5个
            analysis = {
                "original_finding": finding,
                "call_chain": [{"info": "需要手动分析调用链"}],
                "data_flow": {
                    "source": "unknown",
                    "parameter": finding.get("parameter", "unknown"),
                    "parameter_type": finding.get("parameter_type", "unknown"),
                    "sink": finding["function"] + "()"
                },
                "is_controllable": finding.get("parameter_type") == "variable",
                "confidence": finding.get("confidence", 0.5),
                "reasoning": "低置信度发现，需要人工复核"
            }
            analysis_results.append(analysis)
    
    xrefs_data = {
        "analysis": analysis_results,
        "total_analyzed": len(analysis_results),
        "controllable_count": len([a for a in analysis_results if a.get("is_controllable", False)])
    }
    
    print(f"[XrefsAnalysis] 完成: 分析了 {len(analysis_results)} 个发现")
    
    # 使用 Agent 生成详细分析
    summary_input = {
        "messages": [HumanMessage(content=f"交叉引用分析结果:\n{json.dumps(xrefs_data, indent=2, default=str)}")]
    }
    result = xrefs_agent.invoke(summary_input)
    
    return {
        "messages": result["messages"],
        "xrefs_analysis": xrefs_data,
    }


def verify_node(state: AutoSecState) -> dict:
    """
    Agent 4: 漏洞验证
    验证漏洞真实性，构造 Payload
    """
    print(f"[Verify] 开始漏洞验证...")
    xrefs_data = state.get("xrefs_analysis")
    
    if not xrefs_data or not xrefs_data.get("analysis"):
        print(f"[Verify] 错误: 没有交叉引用分析结果")
        return {
            "messages": state["messages"] + [AIMessage(content="没有交叉引用分析结果可供验证")],
            "verification_results": None,
        }
    
    print(f"[Verify] 收到 {len(xrefs_data.get('analysis', []))} 个分析结果")
    
    verifications = []
    
    for analysis in xrefs_data["analysis"]:
        finding = analysis["original_finding"]
        
        # 验证逻辑
        is_confirmed = (
            analysis["is_controllable"] and 
            analysis["confidence"] > 0.7 and
            finding["parameter_type"] == "variable"
        )
        
        # 根据漏洞类型构造 payload
        vuln_type = finding.get("vuln_type", "command_injection")
        payload = None
        if is_confirmed:
            if vuln_type == "command_injection":
                payload = {
                    "type": "command_injection",
                    "description": "命令注入攻击",
                    "example": "; id; #"
                }
            elif vuln_type == "format_string":
                payload = {
                    "type": "format_string",
                    "description": "格式化字符串攻击",
                    "example": "%s%s%s%s%s%s%s%s%n"
                }
            elif vuln_type == "buffer_overflow":
                payload = {
                    "type": "buffer_overflow",
                    "description": "缓冲区溢出攻击",
                    "example": "A" * 256
                }
            elif vuln_type == "arbitrary_file_read":
                payload = {
                    "type": "arbitrary_file_read",
                    "description": "任意文件读取",
                    "example": "../../../../etc/passwd"
                }
            else:
                payload = {
                    "type": vuln_type,
                    "description": f"{vuln_type}攻击",
                    "example": "N/A"
                }
        
        # 根据漏洞类型确定修复建议
        if vuln_type == "command_injection":
            remediation = {
                "immediate": "替换system()为execve()并严格限制参数",
                "short_term": "添加输入验证和过滤",
                "long_term": "实现命令白名单机制"
            } if is_confirmed else {"action": "人工复核参数来源"}
        elif vuln_type == "format_string":
            remediation = {
                "immediate": "使用printf的格式化参数版本，如printf(\"%s\", user_input)",
                "short_term": "添加输入验证，禁止%字符",
                "long_term": "使用类型安全的日志库"
            } if is_confirmed else {"action": "人工复核参数来源"}
        elif vuln_type == "buffer_overflow":
            remediation = {
                "immediate": "替换strcpy为strncpy，限制拷贝长度",
                "short_term": "启用编译器栈保护(-fstack-protector)",
                "long_term": "使用安全的字符串库"
            } if is_confirmed else {"action": "人工复核参数来源"}
        elif vuln_type == "arbitrary_file_read":
            remediation = {
                "immediate": "验证文件路径，禁止目录遍历",
                "short_term": "使用chroot或沙箱限制文件访问",
                "long_term": "实现文件访问白名单"
            } if is_confirmed else {"action": "人工复核参数来源"}
        else:
            remediation = {
                "immediate": "审查并修复漏洞代码",
                "short_term": "添加输入验证",
                "long_term": "代码安全审计"
            } if is_confirmed else {"action": "人工复核参数来源"}
        
        verification = {
            "vulnerability_id": f"VULN-{finding['binary']}-{finding['line']}",
            "type": vuln_type,
            "status": "confirmed" if is_confirmed else "needs_manual_review",
            "cvss_score": 9.8 if is_confirmed else 5.0,
            "severity": finding["severity"] if is_confirmed else "medium",
            "location": finding["location"],
            "snippet": finding["snippet"],
            
            "exploitability": {
                "prerequisites": ["参数可控"] if is_confirmed else ["需要确认参数来源"],
                "attack_vector": "本地/网络" if is_confirmed else "未知",
                "complexity": "低" if is_confirmed else "未知",
            },
            
            "payload": payload,
            "remediation": remediation
        }
        
        verifications.append(verification)
    
    verification_data = {
        "verification": verifications,
        "summary": {
            "total": len(verifications),
            "confirmed": len([v for v in verifications if v["status"] == "confirmed"]),
            "needs_review": len([v for v in verifications if v["status"] == "needs_manual_review"])
        }
    }
    
    # 限制传给 LLM 的数据量 - 只传摘要和前20个验证结果
    agent_input = {
        "summary": verification_data["summary"],
        "top_verifications": verifications[:20],
        "note": f"共验证 {len(verifications)} 个漏洞，这里只显示前 20 个"
    }
    
    # 使用 Agent 生成验证报告
    summary_input = {
        "messages": [HumanMessage(content=f"漏洞验证结果:\n{json.dumps(agent_input, indent=2, default=str)}")]
    }
    result = verify_agent.invoke(summary_input)
    
    # 保存验证报告
    project = state.get("project_name", "")
    project_dir = get_project_dir(project)
    report_dir = os.path.join(project_dir, "report")
    os.makedirs(report_dir, exist_ok=True)
    
    report_path = os.path.join(report_dir, "vuln_verification_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(verification_data, f, ensure_ascii=False, indent=2)
    
    final_content = result["messages"][-1].content + f"\n\n📁 验证报告已保存: {report_path}"
    result["messages"][-1] = AIMessage(content=final_content)
    
    return {
        "messages": result["messages"],
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
