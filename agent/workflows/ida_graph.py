import json

from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import END, StateGraph

from core.model import model
from core.state import AutoSecState
from tools.firmware.ida_exporter import export_with_ida

summary_agent = create_agent(
    model,
    tools=[],
    system_prompt="""
你是一个固件逆向分析专家。系统已经使用 IDA Pro 完成了二进制文件的导出分析。
请根据导出结果，用中文向用户汇报：
1. 分析了哪个二进制文件，使用的架构；
2. 导出了哪些内容（反编译代码、字符串、导入导出表、内存数据等）；
3. 导出文件的数量和保存位置；
4. 给出分析建议。
""",
)


def ida_export_node(state: AutoSecState) -> dict:
    target = state.get("target_path", "")
    project = state.get("project_name", "")

    if not target or not project:
        return {
            "messages": [AIMessage(content="未提供文件或项目名")],
        }

    # 从最后一条用户消息解析文件名和架构
    filename = target  # 默认用 target_path 作为文件名提示
    architecture = ""

    messages = state.get("messages", [])
    for msg in reversed(messages):
        if hasattr(msg, "content") and isinstance(msg.content, str):
            content = msg.content.lower()
            # 解析架构
            for arch in ["arm64", "aarch64", "x86_64", "amd64", "mips64", "ppc64"]:
                if arch in content:
                    architecture = arch
                    break
            for arch in ["arm", "x86", "mips", "ppc", "riscv"]:
                if arch in content and not architecture:
                    architecture = arch
            break

    # 调用 Tool
    tool_result = export_with_ida.invoke({
        "file_hint": filename,
        "project_name": project,
        "architecture": architecture,
    })

    if "error" in tool_result:
        return {
            "messages": state["messages"] + [AIMessage(content=f"IDA 导出失败: {tool_result['error']}")],
        }

    # 总结
    export_info = json.dumps(tool_result, ensure_ascii=False, indent=2, default=str)
    summary_input = {
        "messages": state["messages"]
        + [HumanMessage(content=f"IDA 导出结果：\n{export_info}")]
    }
    result = summary_agent.invoke(summary_input)

    return {"messages": result["messages"]}


builder = StateGraph(AutoSecState)
builder.add_node("ida_exporter", ida_export_node)
builder.set_entry_point("ida_exporter")
builder.add_edge("ida_exporter", END)

ida_graph = builder.compile()
