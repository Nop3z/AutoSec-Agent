import os

from langchain_core.messages import HumanMessage

from agent.workflows.cert_graph import cert_graph
from agent.workflows.crypto_graph import crypto_graph
from agent.workflows.firmware_graph import firmware_graph
from agent.workflows.network_graph import network_graph
from agent.workflows.vuln_graph import vuln_graph
from agent.workflows.vuln_pipeline_graph import vuln_pipeline_graph
from agent.workflows.specialized_vuln_graph import (
    cmd_injection_graph,
    buffer_overflow_graph,
    format_string_graph,
    file_operation_graph,
)
from agent.workflows.cmd_injection_llm_graph import cmd_injection_llm_graph
from core.state import AutoSecState

OUTPUT_BASE = "data/outputs"


def get_help_text() -> str:
    """返回当前可用的命令列表，后续添加新功能时只需修改此处。"""
    commands = [
        ("/extract", "使用 binwalk -Me 解包固件"),
        ("/extract-by-docker", "使用 Docker 部署的 binwalk 解包固件"),
        ("/export-ai", "从提取的文件生成 AI 分析数据（无需 Ghidra）"),
        ("/protocols", "扫描固件中的通信协议"),
        ("/crypto", "识别固件中的加密算法"),
        ("/certs", "提取固件中的证书和密钥"),
        ("/vuln", "快速漏洞扫描（含污点分析）"),
        ("/vuln-full", "完整漏洞流水线（4-Agent深度分析）"),
        ("/vuln-cmd", "专用命令注入漏洞扫描"),
        ("/vuln-scan-and-llm", "命令注入扫描+LLM深度分析 (可加数量: 50/all)"),
        ("/vuln-bof", "专用缓冲区溢出漏洞扫描"),
        ("/vuln-fmt", "专用格式化字符串漏洞扫描"),
        ("/vuln-file", "专用文件操作漏洞扫描"),
        ("/help", "显示可用命令"),
        ("/exit", "退出程序"),
    ]
    lines = ["可用命令:"]
    for cmd, desc in commands:
        lines.append(f"  {cmd:<16} - {desc}")
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
        "vuln_scan_result": None,
        "vuln_scan_complete": None,
        "recon_data": None,
        "cmd_inject_findings": None,
        "xrefs_analysis": None,
        "verification_results": None,
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
                # 使用本地 binwalk -Me 解包
                import subprocess
                import os
                
                project_dir = os.path.join(OUTPUT_BASE, project_name)
                firmware_path = state.get("target_path", "")
                
                if not firmware_path or not os.path.exists(firmware_path):
                    print(f"❌ 未找到固件文件: {firmware_path}")
                    continue
                
                extractions_dir = os.path.join(project_dir, "extractions")
                os.makedirs(extractions_dir, exist_ok=True)
                
                print(f"📦 使用 binwalk -Me 解包固件...")
                print(f"   固件: {firmware_path}")
                print(f"   输出目录: {extractions_dir}")
                
                try:
                    result = subprocess.run(
                        ["binwalk", "-Me", firmware_path],
                        cwd=extractions_dir,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        print(f"✅ 解包完成")
                        print(f"   输出: {extractions_dir}/{os.path.basename(firmware_path)}.extracted/")
                        if result.stdout:
                            print(f"\n📋 binwalk 输出:\n{result.stdout[:500]}")
                    else:
                        print(f"❌ 解包失败: {result.stderr}")
                        
                except FileNotFoundError:
                    print(f"❌ 未找到 binwalk 命令，请确保已安装 binwalk")
                except subprocess.TimeoutExpired:
                    print(f"❌ 解包超时（5分钟）")
                except Exception as e:
                    print(f"❌ 解包出错: {e}")
                
                continue
                
            elif cmd == "/extract-by-docker":
                state["messages"].append(HumanMessage(content="使用 Docker 部署的 binwalk 解包固件"))
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
            elif cmd == "/vuln":
                state["messages"].append(HumanMessage(content="对 export-for-ai 目录下的二进制导出结果进行漏洞扫描"))
                graph = vuln_graph
            elif cmd == "/vuln-full":
                state["messages"].append(HumanMessage(content="启动完整漏洞分析流水线：信息侦查→高危函数侦查→交叉引用分析→漏洞验证"))
                graph = vuln_pipeline_graph
            elif cmd == "/vuln-cmd":
                state["messages"].append(HumanMessage(content="执行专用命令注入漏洞扫描"))
                graph = cmd_injection_graph
            elif cmd == "/vuln-scan-and-llm":
                parts = user_input.split()
                limit_arg = parts[1] if len(parts) > 1 else "15"
                if limit_arg.lower() == "all":
                    limit_val = 0
                else:
                    try:
                        limit_val = int(limit_arg)
                    except ValueError:
                        limit_val = 15
                from agent.workflows.cmd_injection_llm_graph import set_max_findings
                set_max_findings(limit_val)
                state["messages"].append(HumanMessage(content="执行命令注入扫描+LLM深度分析"))
                graph = cmd_injection_llm_graph
            elif cmd == "/vuln-bof":
                state["messages"].append(HumanMessage(content="执行专用缓冲区溢出漏洞扫描"))
                graph = buffer_overflow_graph
            elif cmd == "/vuln-fmt":
                state["messages"].append(HumanMessage(content="执行专用格式化字符串漏洞扫描"))
                graph = format_string_graph
            elif cmd == "/vuln-file":
                state["messages"].append(HumanMessage(content="执行专用文件操作漏洞扫描"))
                graph = file_operation_graph
            elif cmd == "/export-ai":
                # 直接调用导出生成器
                from tools.export_ai_generator import generate_export_for_ai
                print(f"正在为项目 '{project_name}' 生成 AI 分析数据...")
                result = generate_export_for_ai(project_name)
                if result["success"]:
                    print(f"✅ {result['message']}")
                    for b in result["binaries"]:
                        print(f"   - {b['name']} ({b['original_path']})")
                else:
                    print(f"❌ {result['message']}")
                continue
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
        try:
            for event in graph.stream(state, stream_mode="values"):
                final_event = event
        except Exception as e:
            print(f"Graph 执行出错: {e}")
            import traceback
            traceback.print_exc()
            continue

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
