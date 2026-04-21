"""
命令注入漏洞扫描 + LLM 深度分析工作流

两阶段流水线：
1. scan_node: Python 正则扫描命令注入高危函数，构建调用链
2. llm_analysis_node: LLM + 工具遍历调用链上每个函数，分析可利用性，生成 POC

命令: /vuln-scan-and-llm
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
from agent.workflows.specialized_vuln_graph import (
    _scan_vuln_by_type,
    _save_specialized_report,
)
from tools.vuln.xref_tools import read_decompiled_function, lookup_function_xrefs


# ============== 配置 ==============

MAX_FINDINGS = 15


def set_max_findings(n: int):
    """设置最大分析数量。0 表示不限制。"""
    global MAX_FINDINGS
    MAX_FINDINGS = n

CMD_INJECTION_LLM_PROMPT = """你是命令注入漏洞分析专家。你的任务是分析反编译代码中的命令注入漏洞。

你有两个工具：
1. **read_decompiled_function**: 读取一个反编译函数的完整源码
   - 参数: project_name, binary_name, identifier (函数名或文件名如 "3068.c")
2. **lookup_function_xrefs**: 查询函数的调用关系
   - 参数: project_name, binary_name, identifier (函数名或地址如 "0x3068")

## 工作流程

你会收到一个命令注入漏洞发现及其调用链。请按以下步骤分析：

1. **遍历调用链**：用 read_decompiled_function 逐个读取调用链上每个函数的完整代码
2. **追踪参数传递**：从漏洞点（如 popen(v8)）开始，向上追踪 v8 的来源，看它在每个函数中如何被赋值和传递
3. **判断可控性**：
   - 参数来自 recv/socket/read/fgets/getenv/argv/CGI/用户输入接口 → 外部可控，高危
   - 参数来自硬编码字符串常量 → 不可控，误报
   - 参数经过 strncpy 限长但无命令字符过滤 → 仍可利用（长度限制不防命令注入）
   - 参数经过白名单校验或 shell 转义 → 已净化，风险降低
4. **给出结论**：exploitable（可利用）/ needs_review（需人工复核）/ false_positive（误报）
5. **如果可利用**：构造具体的 POC（Proof of Concept），说明攻击路径

## 输出格式

请严格按以下 JSON 格式输出：
```json
{
  "status": "exploitable",
  "severity": "critical",
  "data_flow": "参数从 XX 传入，经 YY 函数传递到 ZZ，最终到达 popen()",
  "sanitization": "无过滤 / strncpy限长但无命令字符过滤 / ...",
  "poc": "具体的利用方式或 payload",
  "remediation": "修复建议",
  "reasoning": "判断依据的简要说明"
}
```
"""


# ============== Agent 创建 ==============

xref_tools = [read_decompiled_function, lookup_function_xrefs]
analysis_agent = create_agent(model, tools=xref_tools, system_prompt=CMD_INJECTION_LLM_PROMPT)


# ============== 辅助函数 ==============

def _extract_chain_functions(call_chain: str) -> list[str]:
    """从调用链字符串中提取函数名列表"""
    return re.findall(r"(\w+)\s*\(", call_chain)


def _parse_llm_result(agent_response: str) -> dict:
    """从 LLM 响应中提取结构化结果"""
    json_match = re.search(r"\{[^{}]*\"status\"[^{}]*\}", agent_response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    response_lower = agent_response.lower()
    if any(kw in response_lower for kw in ["exploitable", "可利用", "高危", "confirmed"]):
        status = "exploitable"
    elif any(kw in response_lower for kw in ["false_positive", "误报", "不可控", "hardcoded"]):
        status = "false_positive"
    else:
        status = "needs_review"

    return {
        "status": status,
        "severity": "critical" if status == "exploitable" else "medium",
        "reasoning": agent_response[:500],
    }


def _save_llm_report(project_dir: str, by_binary: dict[str, list]):
    """保存 LLM 分析报告，按 binary 分组"""
    saved = []
    for binary_name, findings in by_binary.items():
        dir_name = "command-injection-llm"
        report_dir = os.path.join(project_dir, "report", binary_name, dir_name)
        os.makedirs(report_dir, exist_ok=True)

        summary = {
            "binary": binary_name,
            "vuln_type": "command_injection",
            "analysis_method": "regex_scan + llm_deep_analysis",
            "total_findings": len(findings),
            "exploitable": len([f for f in findings if f.get("llm_status") == "exploitable"]),
            "needs_review": len([f for f in findings if f.get("llm_status") == "needs_review"]),
            "false_positive": len([f for f in findings if f.get("llm_status") == "false_positive"]),
            "findings": findings,
        }

        json_path = os.path.join(report_dir, "command_injection_llm_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2, default=str)

        md_path = os.path.join(report_dir, "command_injection_llm_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# {binary_name} - 命令注入漏洞深度分析报告\n\n")
            f.write(f"**分析方法**: Python 正则扫描 + LLM 深度分析\n")
            f.write(f"**发现总数**: {len(findings)}\n")
            f.write(f"**可利用**: {summary['exploitable']} | ")
            f.write(f"**需人工复核**: {summary['needs_review']} | ")
            f.write(f"**误报**: {summary['false_positive']}\n\n")
            f.write("---\n\n")

            for i, finding in enumerate(findings, 1):
                status_icon = {"exploitable": "!!!", "needs_review": "?", "false_positive": "x"}.get(
                    finding.get("llm_status", ""), "?"
                )
                f.write(f"## {i}. [{status_icon}] {finding['function']}() @ {finding['location']}\n\n")
                f.write(f"- **严重程度**: {finding.get('severity', 'unknown')}\n")
                f.write(f"- **置信度**: {finding.get('confidence', 0):.2f}\n")
                f.write(f"- **参数**: `{finding.get('parameter', 'unknown')}`\n")
                f.write(f"- **参数类型**: {finding.get('parameter_type', 'unknown')}\n")
                f.write(f"- **调用链**: `{finding.get('call_chain', 'N/A')}`\n")
                f.write(f"- **代码片段**: `{finding.get('snippet', '')[:100]}`\n")
                f.write(f"- **LLM 判定**: **{finding.get('llm_status', 'unknown')}**\n\n")

                llm = finding.get("llm_result", {})
                if llm.get("data_flow"):
                    f.write(f"**数据流**: {llm['data_flow']}\n\n")
                if llm.get("sanitization"):
                    f.write(f"**净化措施**: {llm['sanitization']}\n\n")
                if llm.get("poc"):
                    f.write(f"**POC**:\n```\n{llm['poc']}\n```\n\n")
                if llm.get("remediation"):
                    f.write(f"**修复建议**: {llm['remediation']}\n\n")
                if llm.get("reasoning"):
                    f.write(f"**分析依据**: {llm['reasoning']}\n\n")

                f.write("---\n\n")

        saved.append({
            "binary": binary_name,
            "count": len(findings),
            "json": json_path,
            "markdown": md_path,
        })

    return saved


# ============== 节点函数 ==============

def scan_node(state: AutoSecState) -> dict:
    """Python 正则扫描命令注入高危函数，构建调用链"""
    print("[CmdScan] 开始命令注入扫描...")
    project = state.get("project_name", "")
    if not project:
        print("[CmdScan] 跳过: project_name 为空")
        return {
            "messages": state["messages"] + [AIMessage(content="未提供项目名")],
            "cmd_inject_findings": None,
        }

    project_dir = get_project_dir(project)
    export_base = os.path.join(project_dir, "export-for-ai")

    if not os.path.exists(export_base):
        print(f"[CmdScan] 跳过: 导出目录不存在 {export_base}")
        return {
            "messages": state["messages"] + [AIMessage(content=f"未找到导出目录: {export_base}")],
            "cmd_inject_findings": None,
        }

    findings = _scan_vuln_by_type(export_base, "command_injection")
    print(f"[CmdScan] 扫描完成: 发现 {len(findings)} 个命令注入调用")

    actionable = [f for f in findings if f.get("parameter_type") != "hardcoded"]
    actionable.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    selected = actionable[:MAX_FINDINGS] if MAX_FINDINGS > 0 else actionable

    print(f"[CmdScan] 筛选出 {len(selected)} 个非硬编码发现 (从 {len(findings)} 个中)")
    for i, f in enumerate(selected[:5]):
        print(f"  [{i+1}] {f['function']}() @ {f['location']} ({f['parameter_type']})")
    if len(selected) > 5:
        print(f"  ... 还有 {len(selected) - 5} 个")

    scan_data = {
        "findings": selected,
        "all_count": len(findings),
        "actionable_count": len(selected),
    }

    summary = (
        f"命令注入扫描完成：共 {len(findings)} 个调用，"
        f"筛选出 {len(selected)} 个非硬编码发现待 LLM 深度分析。"
    )

    return {
        "messages": state["messages"] + [AIMessage(content=summary)],
        "cmd_inject_findings": scan_data,
    }


def llm_analysis_node(state: AutoSecState) -> dict:
    """LLM 遍历调用链上的函数，深度分析漏洞可利用性"""
    print("[LLMAnalysis] 开始 LLM 深度分析...")
    scan_data = state.get("cmd_inject_findings")

    if not scan_data or not scan_data.get("findings"):
        print("[LLMAnalysis] 跳过: 无扫描结果")
        return {
            "messages": state["messages"] + [AIMessage(content="没有命令注入发现可供分析")],
            "vuln_findings": None,
        }

    project = state.get("project_name", "")
    project_dir = get_project_dir(project)
    findings = scan_data["findings"]

    analyzed = []

    for i, finding in enumerate(findings):
        func_name = finding["function"]
        location = finding["location"]
        binary = finding["binary"]
        call_chain = finding.get("call_chain", "")
        chain_funcs = _extract_chain_functions(call_chain)

        print(f"[LLMAnalysis] [{i+1}/{len(findings)}] {func_name}() @ {location} (链上 {len(chain_funcs)} 个函数)")

        prompt = (
            f"请分析以下命令注入漏洞。\n\n"
            f"**漏洞信息**:\n"
            f"- 项目名: {project}\n"
            f"- 二进制: {binary}\n"
            f"- 危险函数: {func_name}()\n"
            f"- 位置: {location}\n"
            f"- 代码片段: {finding.get('snippet', '')}\n"
            f"- 参数: {finding.get('parameter', 'unknown')}\n"
            f"- 调用链: {call_chain}\n\n"
            f"**请按以下步骤操作**:\n"
            f"1. 用 read_decompiled_function 依次读取调用链上的每个函数: {', '.join(chain_funcs)}\n"
            f"2. 追踪 {finding.get('parameter', '参数')} 在调用链中的传递过程\n"
            f"3. 判断参数是否外部可控\n"
            f"4. 给出 JSON 格式的分析结论\n"
        )

        try:
            result = analysis_agent.invoke({
                "messages": [HumanMessage(content=prompt)]
            })
            agent_response = result["messages"][-1].content
            llm_result = _parse_llm_result(agent_response)
        except Exception as e:
            print(f"[LLMAnalysis] Agent 出错: {e}")
            agent_response = f"分析失败: {str(e)}"
            llm_result = {"status": "needs_review", "reasoning": str(e)}

        entry = {
            **finding,
            "llm_analysis": agent_response,
            "llm_result": llm_result,
            "llm_status": llm_result.get("status", "needs_review"),
            "severity": llm_result.get("severity", finding.get("severity", "medium")),
        }
        analyzed.append(entry)

        status = llm_result.get("status", "unknown")
        print(f"  → {status}")

    # 按 binary 分组保存报告
    by_binary: dict[str, list] = {}
    for f in analyzed:
        by_binary.setdefault(f["binary"], []).append(f)

    saved = _save_llm_report(project_dir, by_binary)

    for r in saved:
        print(f"  [{r['binary']}] {r['count']} 个漏洞 → report/{r['binary']}/command-injection-llm/")

    # 生成汇总
    exploitable_count = len([a for a in analyzed if a["llm_status"] == "exploitable"])
    review_count = len([a for a in analyzed if a["llm_status"] == "needs_review"])
    fp_count = len([a for a in analyzed if a["llm_status"] == "false_positive"])

    report_info = "\n".join(
        f"- `{r['binary']}`: {r['count']} 个 → `report/{r['binary']}/command-injection-llm/`"
        for r in saved
    )

    summary = (
        f"命令注入 LLM 深度分析完成：\n"
        f"- 分析: {len(analyzed)} 个发现\n"
        f"- 可利用: {exploitable_count}\n"
        f"- 需人工复核: {review_count}\n"
        f"- 误报: {fp_count}\n\n"
        f"报告已保存:\n{report_info}"
    )

    return {
        "messages": state["messages"] + [AIMessage(content=summary)],
        "vuln_findings": analyzed,
    }


# ============== 构建工作流 ==============

builder = StateGraph(AutoSecState)
builder.add_node("scan", scan_node)
builder.add_node("llm_analysis", llm_analysis_node)
builder.set_entry_point("scan")
builder.add_edge("scan", "llm_analysis")
builder.add_edge("llm_analysis", END)

cmd_injection_llm_graph = builder.compile()
