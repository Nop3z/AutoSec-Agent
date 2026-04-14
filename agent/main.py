import os

import os

from langchain_core.messages import HumanMessage

from agent.workflows.cert_graph import cert_graph
from agent.workflows.crypto_graph import crypto_graph
from agent.workflows.firmware_graph import firmware_graph
from agent.workflows.network_graph import network_graph
from core.state import AutoSecState

OUTPUT_BASE = "data/outputs"


def get_help_text() -> str:
    """返回当前可用的命令列表，后续添加新功能时只需修改此处。"""
    commands = [
        ("/extract", "使用 binwalk 解包固件"),
        ("/protocols", "扫描固件中的通信协议"),
        ("/crypto", "识别固件中的加密算法"),
        ("/certs", "提取固件中的证书和密钥"),
        ("/help", "显示可用命令"),
        ("/exit", "退出程序"),
    ]
    lines = ["可用命令:"]
    for cmd, desc in commands:
        lines.append(f"  {cmd:<12} - {desc}")
    return "\n".join(lines)


def list_projects() -> list[str]:
    """列出已有项目目录名"""
    if not os.path.exists(OUTPUT_BASE):
        return []
    return sorted([d for d in os.listdir(OUTPUT_BASE) if os.path.isdir(os.path.join(OUTPUT_BASE, d))])


def prompt_project() -> tuple[str, str]:
    """
    交互式选择项目。
    返回 (project_name, target_path)
    """
    projects = list_projects()

    print("=== 项目选择 ===")
    if projects:
        print("已有项目:")
        for idx, name in enumerate(projects, 1):
            print(f"  [{idx}] {name}")
        print("  [n] 新建项目")
        choice = input("请选择 (序号/n): ").strip()

        if choice.lower() != "n":
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(projects):
                    project_name = projects[idx]
                    extractions = os.path.join(OUTPUT_BASE, project_name, "extractions")
                    target = extractions if os.path.isdir(extractions) else os.path.join(OUTPUT_BASE, project_name)
                    return project_name, target
                else:
                    print("无效序号，将创建新项目。")
            except ValueError:
                print("输入无效，将创建新项目。")
    else:
        print("暂无已有项目，将创建新项目。")

    project_name = input("请输入新项目名: ").strip()
    target = input("请输入固件路径: ").strip()

    if not project_name or not target:
        print("项目名或路径为空，退出。")
        exit(1)

    return project_name, target


def main():
    print("=== AutoSec Agent (MVP) ===\n")

    project_name, target = prompt_project()

    # 初始化 State（LangGraph 的传送带）
    state: AutoSecState = {
        "messages": [],
        "project_name": project_name,
        "target_path": target,
        "input_type": "firmware",
        "firmware_crypto": None,
        "firmware_certs": None,
        "firmware_algo27": None,
        "firmware_chip": None,
        "firmware_cockpit": None,
        "network_topology": None,
        "network_tps_addrs": None,
        "network_routes": None,
        "network_protocols": None,
        "oss_components": None,
        "vuln_findings": None,
        "report_markdown": None,
    }

    print(f"\n项目: {project_name}")
    print(f"目标路径: {target}")
    print(f"\n{get_help_text()}")

    while True:
        user_input = input("\n用户: ").strip()
        if user_input.lower() in ("/exit", "/quit"):
            print("再见！")
            break

        if not user_input:
            continue

        # 命令分发
        if user_input.startswith("/"):
            cmd = user_input.split()[0].lower()

            if cmd == "/extract":
                state["messages"].append(HumanMessage(content="帮我解包这个固件"))
                graph = firmware_graph
            elif cmd == "/protocols":
                state["messages"].append(HumanMessage(content="识别这个固件中的通信协议"))
                graph = network_graph
            elif cmd == "/crypto":
                state["messages"].append(HumanMessage(content="识别这个固件中的加密算法"))
                graph = crypto_graph
            elif cmd == "/certs":
                state["messages"].append(HumanMessage(content="提取这个固件中的证书和密钥"))
                graph = cert_graph
            elif cmd == "/help":
                print(get_help_text())
                continue
            else:
                print(f"未知命令: {cmd}\n{get_help_text()}")
                continue
        else:
            # 当前所有功能均通过 / 命令触发
            print(f"未知输入: '{user_input}'\n{get_help_text()}")
            continue

        # 调用选定的 Graph
        final_event = None
        for event in graph.stream(state, stream_mode="values"):
            final_event = event

        if final_event is None:
            print("AI: 无响应")
            continue

        state = final_event
        last_msg = state["messages"][-1]
        print(f"AI: {last_msg.content}")

        # 更新 target_path（解包后可能变化）
        if state.get("target_path"):
            target = state["target_path"]

        # DEBUG 信息
        if state.get("network_protocols"):
            print(f"\n[DEBUG] 识别到的协议: {state['network_protocols']}")


if __name__ == "__main__":
    main()
