import json

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.state import AutoSecState
from tools.firmware.cert_extractor import extract_certificates

# 总结 Agent：不调用工具，只负责把证书提取结果用中文汇报给用户
summary_agent = create_agent(
    model,
    tools=[],
    system_prompt="""
你是一个固件安全分析专家。系统已经完成了固件中的证书和密钥提取。
请根据提取结果，用中文向用户汇报：
1. 总共提取了多少个证书/密钥；
2. 独立证书文件和嵌入证书的数量；
3. 证书保存的位置（Certificate/ 目录结构）；
4. 给出安全建议（如是否存在明文私钥、是否需要检查证书有效期等）。
""",
)


def cert_node(state: AutoSecState) -> dict:
    """
    直接调用 extract_certificates 工具提取证书，
    再用 summary_agent 生成中文总结。
    """
    target = state.get("target_path", "")
    project = state.get("project_name", "")

    if not target or not project:
        return {
            "messages": [AIMessage(content="未提供固件路径或项目名，无法提取证书。")],
            "firmware_certs": None,
        }

    # 1. 直接调用 Tool（传入 project_name 用于路径校验）
    tool_result = extract_certificates.invoke({
        "firmware_path": target,
        "project_name": project,
    })

    if "error" in tool_result:
        error_msg = f"证书提取失败: {tool_result['error']}"
        return {
            "messages": state["messages"] + [AIMessage(content=error_msg)],
            "firmware_certs": None,
        }

    # 2. 让 summary_agent 做总结
    scan_info = json.dumps(tool_result, ensure_ascii=False, indent=2)
    summary_input = {
        "messages": state["messages"]
        + [
            HumanMessage(
                content=f"固件证书提取结果如下（路径: {target}）：\n{scan_info}"
            )
        ]
    }
    result = summary_agent.invoke(summary_input)

    return {
        "messages": result["messages"],
        "firmware_certs": [tool_result],
    }


builder = StateGraph(AutoSecState)
builder.add_node("cert_extractor", cert_node)
builder.set_entry_point("cert_extractor")
builder.add_edge("cert_extractor", END)

cert_graph = builder.compile()
