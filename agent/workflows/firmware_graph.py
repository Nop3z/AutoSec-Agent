import json

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.state import AutoSecState
from tools.firmware.extractor import extract_firmware

# 总结 Agent：不调用工具，只负责把解包结果用中文汇报给用户
summary_agent = create_agent(
    model,
    tools=[],
    system_prompt="""
你是一个固件分析助手。系统已经使用 binwalk 完成了固件解包。
请根据解包结果，用中文向用户汇报：
1. 项目创建在哪个目录；
2. 解包出了多少个文件；
3. 列出一些关键文件（如果有）；
4. 告诉用户接下来可以在 extractions/ 目录里查看解包内容，report/ 目录会存放最终报告，Certificate/ 目录会存放提取的证书。
""",
)


def extract_node(state: AutoSecState) -> dict:
    """
    直接调用 extract_firmware 工具解包，
    再用 summary_agent 生成中文总结。
    """
    target = state.get("target_path", "")
    project = state.get("project_name", "")

    if not target or not project:
        return {
            "messages": [AIMessage(content="未提供固件路径或项目名，无法解包。")],
        }

    # 1. 直接调用 Tool
    tool_result = extract_firmware.invoke({
        "firmware_path": target,
        "project_name": project,
    })

    if "error" in tool_result:
        error_msg = f"解包失败: {tool_result['error']}"
        if tool_result.get("stdout"):
            error_msg += f"\n[stdout] {tool_result['stdout']}"
        if tool_result.get("stderr"):
            error_msg += f"\n[stderr] {tool_result['stderr']}"
        return {
            "messages": state["messages"] + [AIMessage(content=error_msg)],
        }

    # 2. 让 summary_agent 做总结
    scan_info = json.dumps(tool_result, ensure_ascii=False, indent=2)
    summary_input = {
        "messages": state["messages"]
        + [
            HumanMessage(
                content=f"固件解包结果如下（项目: {project}）：\n{scan_info}"
            )
        ]
    }
    result = summary_agent.invoke(summary_input)

    return {
        "messages": result["messages"],
        "target_path": tool_result.get("extractions_dir", target),
    }


builder = StateGraph(AutoSecState)
builder.add_node("firmware_extractor", extract_node)
builder.set_entry_point("firmware_extractor")
builder.add_edge("firmware_extractor", END)

firmware_graph = builder.compile()
