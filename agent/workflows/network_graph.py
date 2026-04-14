import json

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.state import AutoSecState
from tools.network.protocol_identifier import identify_protocol

# 总结 Agent：不调用工具，只负责把协议扫描结果用中文汇报给用户
summary_agent = create_agent(
    model,
    tools=[],
    system_prompt="""
你是一个汽车网络安全分析专家。系统已经完成了固件中的通信协议扫描。
请根据扫描结果，用中文向用户汇报：
1. 识别到了哪些通信协议；
2. 发现的关键文件和字符串证据；
3. 给出安全建议（如是否存在明文传输风险、是否需要进一步分析 TLS 配置等）。
""",
)


def network_node(state: AutoSecState) -> dict:
    """
    直接调用 identify_protocol 工具扫描协议，
    再用 summary_agent 生成中文总结。
    """
    target = state.get("target_path", "")
    project = state.get("project_name", "")

    if not target or not project:
        return {
            "messages": [AIMessage(content="未提供固件路径或项目名，无法扫描协议。")],
            "network_protocols": None,
        }

    # 1. 直接调用 Tool（传入 project_name 用于路径校验）
    tool_result = identify_protocol.invoke({
        "firmware_path": target,
        "project_name": project,
    })

    if "error" in tool_result:
        error_msg = f"扫描失败: {tool_result['error']}"
        return {
            "messages": state["messages"] + [AIMessage(content=error_msg)],
            "network_protocols": None,
        }

    # 2. 让 summary_agent 做总结
    scan_info = json.dumps(tool_result, ensure_ascii=False, indent=2)
    summary_input = {
        "messages": state["messages"]
        + [
            HumanMessage(
                content=f"固件协议扫描结果如下（路径: {target}）：\n{scan_info}"
            )
        ]
    }
    result = summary_agent.invoke(summary_input)

    return {
        "messages": result["messages"],
        "network_protocols": [tool_result],
    }


builder = StateGraph(AutoSecState)
builder.add_node("network_analyzer", network_node)
builder.set_entry_point("network_analyzer")
builder.add_edge("network_analyzer", END)

network_graph = builder.compile()
