"""
漏洞扫描工作流 v2：支持污点分析和按文件生成独立报告。

工作流节点：
1. scan_node: 规则扫描，生成候选漏洞列表
2. taint_analysis_node: 污点分析，过滤误报
3. report_node: 生成汇总报告和 LLM 分析报告
"""

import json
import os

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.path_guard import get_project_dir
from core.state import AutoSecState
from tools.vuln.vuln_scanner_v2 import scan_vulnerabilities_v2

# 汇总报告 Agent
summary_agent = create_agent(
    model,
    tools=[],
    system_prompt="""
你是一位资深的汽车网络安全与嵌入式漏洞分析专家。

系统已经完成对固件二进制导出文件的自动化漏洞扫描，并经过了污点分析过滤。

请根据扫描结果，用中文向用户输出一份专业的漏洞分析报告，包含：
1. 扫描了哪些二进制文件；
2. 各类漏洞的数量统计（按严重等级分组）；
3. 重点漏洞详细说明（包括漏洞类型、所在文件/行号、代码片段、污点分析结果）；
4. 攻击场景与修复建议；
5. 下一步分析建议。

对于每个确认的漏洞，请特别关注：
- 参数可控性分析结果
- 利用可能性评估
- 具体的攻击场景描述

请保持报告结构清晰、便于阅读。
""",
)


def scan_node(state: AutoSecState) -> dict:
    """
    节点1: 执行规则扫描和污点分析
    """
    project = state.get("project_name", "")
    
    if not project:
        return {
            "messages": state["messages"] + [AIMessage(content="未提供项目名，无法进行漏洞扫描。")],
            "vuln_findings": None,
            "vuln_scan_complete": False,
        }

    # 调用扫描工具（内部包含污点分析）
    try:
        tool_result = scan_vulnerabilities_v2.invoke({
            "project_name": project,
            "enable_taint_analysis": True,
            "taint_batch_size": 5,  # 控制 API 调用频率
        })
    except Exception as e:
        return {
            "messages": state["messages"] + [AIMessage(content=f"漏洞扫描失败: {str(e)}")],
            "vuln_findings": None,
            "vuln_scan_complete": False,
        }

    if "error" in tool_result:
        return {
            "messages": state["messages"] + [AIMessage(content=f"漏洞扫描失败: {tool_result['error']}")],
            "vuln_findings": None,
            "vuln_scan_complete": False,
        }

    # 保存扫描结果到 state
    return {
        "messages": state["messages"] + [
            AIMessage(content=f"漏洞扫描完成，正在生成报告...")
        ],
        "vuln_scan_result": tool_result,
        "vuln_scan_complete": True,
    }


def report_node(state: AutoSecState) -> dict:
    """
    节点2: 生成汇总报告
    """
    tool_result = state.get("vuln_scan_result", {})
    
    if not tool_result:
        return {
            "messages": state["messages"] + [AIMessage(content="没有扫描结果可供报告。")],
            "vuln_findings": [],
        }

    scanned_binaries = tool_result.get("scanned_binaries", [])
    summary = tool_result.get("summary", {})
    confirmed_count = tool_result.get("confirmed_findings_count", 0)
    fp_count = tool_result.get("false_positive_count", 0)
    
    # 如果没有发现漏洞
    if confirmed_count == 0:
        msg = (
            f"已完成对 {', '.join(scanned_binaries)} 的漏洞扫描。\n\n"
            f"扫描统计:\n"
            f"- 候选漏洞: {summary.get('total_confirmed', 0) + fp_count} 个\n"
            f"- 经污点分析过滤后确认: {confirmed_count} 个\n"
            f"- 误报/低风险: {fp_count} 个\n\n"
            f"未发现需要关注的高风险漏洞。\n\n"
            f"📁 报告位置:\n"
            f"- 主报告: {tool_result.get('master_report', 'N/A')}\n"
        )
        return {
            "messages": state["messages"] + [AIMessage(content=msg)],
            "vuln_findings": [],
        }

    # 读取主报告获取详细信息
    master_report_path = tool_result.get("master_report", "")
    confirmed_findings = []
    
    if master_report_path and os.path.exists(master_report_path):
        try:
            with open(master_report_path, "r", encoding="utf-8") as f:
                master_data = json.load(f)
            confirmed_findings = master_data.get("all_confirmed_findings", [])
        except Exception:
            pass

    # 构建 LLM 分析输入
    scan_info = {
        "项目": tool_result.get("project", ""),
        "扫描的二进制文件": scanned_binaries,
        "统计摘要": summary,
        "确认的漏洞数量": confirmed_count,
        "误报数量": fp_count,
        "各二进制报告": [
            {
                "binary": r["binary"],
                "summary": r["summary"],
                "report_path": r["binary_report"],
            }
            for r in tool_result.get("binary_reports", [])
        ],
        # 选取前 20 个漏洞作为示例（避免超出上下文）
        "重点漏洞示例": confirmed_findings[:20],
    }
    
    scan_info_json = json.dumps(scan_info, ensure_ascii=False, indent=2, default=str)
    
    # 调用 summary_agent 生成报告
    try:
        summary_input = {
            "messages": state["messages"] + [
                HumanMessage(content=f"漏洞扫描与污点分析结果如下：\n{scan_info_json}")
            ]
        }
        result = summary_agent.invoke(summary_input)
        
        # 追加报告路径信息
        report_paths = [
            f"📁 主报告: {tool_result.get('master_report', 'N/A')}",
            "📁 各二进制独立报告:",
        ]
        for br in tool_result.get("binary_reports", [])[:5]:  # 只显示前5个
            report_paths.append(f"  - {br['binary']}: {br['binary_report']}")
            if len(br.get("file_reports", [])) > 0:
                report_paths.append(f"    文件级报告: {len(br['file_reports'])} 个")
        
        final_content = result["messages"][-1].content + "\n\n" + "\n".join(report_paths)
        result["messages"][-1] = AIMessage(content=final_content)
        
        return {
            "messages": result["messages"],
            "vuln_findings": confirmed_findings,
            "vuln_scan_result": tool_result,
        }
        
    except Exception as e:
        # 如果 LLM 分析失败，返回基础报告
        msg = (
            f"漏洞扫描完成，但生成详细报告时出错: {str(e)}\n\n"
            f"扫描统计:\n"
            f"- 扫描的二进制: {', '.join(scanned_binaries)}\n"
            f"- 确认漏洞: {confirmed_count} 个\n"
            f"- 误报过滤: {fp_count} 个\n\n"
            f"📁 报告位置: {master_report_path}"
        )
        return {
            "messages": state["messages"] + [AIMessage(content=msg)],
            "vuln_findings": confirmed_findings,
            "vuln_scan_result": tool_result,
        }


# 构建工作流
builder = StateGraph(AutoSecState)

# 添加节点
builder.add_node("vuln_scanner", scan_node)
builder.add_node("report_generator", report_node)

# 设置入口和边
builder.set_entry_point("vuln_scanner")
builder.add_edge("vuln_scanner", "report_generator")
builder.add_edge("report_generator", END)

vuln_graph = builder.compile()
