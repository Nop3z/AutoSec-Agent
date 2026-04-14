from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from dotenv import load_dotenv

import sqlite3
import uuid
import os
import json

load_dotenv()

DB_PATH = "checkpoints.sqlite"
META_PATH = "sessions.json"


# ------------------- 模型与 Agent -------------------
model = init_chat_model(
    model_provider="openrouter",
    model="gpt-4o",
)

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
checkpointer = SqliteSaver(conn)

agent = create_agent(
    model,
    tools=[],
    checkpointer=checkpointer,
    system_prompt="你是一个AI助手，协助用户解答问题。",
)


# ------------------- 会话元数据管理 -------------------
def load_meta():
    if os.path.exists(META_PATH):
        with open(META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_meta(meta):
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def list_threads():
    """从 checkpoint 数据库中读取所有已有对话记录的 thread_id"""
    threads = set()
    for cp in checkpointer.list(None):
        tid = cp.config["configurable"]["thread_id"]
        threads.add(tid)
    return threads


def get_session_name(tid, sessions):
    return sessions.get(tid, "未命名会话")


def print_help():
    print("""
可用命令：
  /new [名称]     - 创建新会话
  /list           - 列出所有会话
  /switch <id>    - 切换到指定会话
  /rename <名称>  - 重命名当前会话
  /delete <id>    - 删除指定会话
  /current        - 显示当前会话信息
  /exit /quit     - 退出程序
""")


# ------------------- 初始化会话 -------------------
sessions = load_meta()
all_db_threads = list_threads()

# 清理 JSON 中已不存在于数据库的残留记录（保留当前可能刚新建但未对话的会话）
for tid in list(sessions.keys()):
    if tid not in all_db_threads:
        sessions.pop(tid, None)

if sessions:
    current_thread = list(sessions.keys())[0]
else:
    current_thread = str(uuid.uuid4())[:8]
    sessions[current_thread] = "默认会话"
    save_meta(sessions)

print(f"当前会话: [{current_thread}] {get_session_name(current_thread, sessions)}")
print_help()


# ------------------- 主循环 -------------------
while True:
    try:
        user_input = input("\n用户: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n再见！")
        break

    if not user_input:
        continue

    if user_input.lower() in ("/exit", "/quit"):
        print("对话结束。")
        break

    # --------------- 命令处理 ---------------
    if user_input.startswith("/"):
        parts = user_input.split(" ", 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "/new":
            current_thread = str(uuid.uuid4())[:8]
            sessions[current_thread] = arg or f"会话 {current_thread}"
            save_meta(sessions)
            print(f"已创建新会话: [{current_thread}] {sessions[current_thread]}")

        elif cmd == "/list":
            all_threads = sorted(set(list_threads()) | set(sessions.keys()))
            if not all_threads:
                print("暂无会话。")
            else:
                print("会话列表:")
                for tid in all_threads:
                    marker = "  *" if tid == current_thread else "   "
                    print(f"{marker} [{tid}] {get_session_name(tid, sessions)}")

        elif cmd == "/switch":
            if not arg:
                print("用法: /switch <thread_id>")
                continue
            if arg not in list_threads() and arg not in sessions:
                print(f"会话 {arg} 不存在。")
                continue
            current_thread = arg
            if current_thread not in sessions:
                sessions[current_thread] = f"会话 {current_thread}"
                save_meta(sessions)
            print(f"已切换到: [{current_thread}] {get_session_name(current_thread, sessions)}")

        elif cmd == "/rename":
            if not arg:
                print("用法: /rename <新名称>")
                continue
            sessions[current_thread] = arg
            save_meta(sessions)
            print(f"已重命名为: [{current_thread}] {arg}")

        elif cmd == "/delete":
            if not arg:
                print("用法: /delete <thread_id>")
                continue
            if arg not in list_threads() and arg not in sessions:
                print(f"会话 {arg} 不存在。")
                continue
            try:
                checkpointer.delete_thread(arg)
            except Exception as e:
                print(f"删除 checkpoint 时出错: {e}")
            sessions.pop(arg, None)
            save_meta(sessions)
            if arg == current_thread:
                remaining = sorted(set(list_threads()) | set(sessions.keys()))
                if remaining:
                    current_thread = remaining[0]
                else:
                    current_thread = str(uuid.uuid4())[:8]
                    sessions[current_thread] = "默认会话"
                    save_meta(sessions)
                print(f"已删除，当前切换到: [{current_thread}] {get_session_name(current_thread, sessions)}")
            else:
                print(f"已删除会话: {arg}")

        elif cmd == "/current":
            print(f"当前会话: [{current_thread}] {get_session_name(current_thread, sessions)}")

        else:
            print("未知命令。")
            print_help()
        continue

    # --------------- 流式对话 ---------------
    config = {"configurable": {"thread_id": current_thread}}
    print("AI: ", end="", flush=True)
    ai_content = ""
    for chunk, metadata in agent.stream(
        {"messages": [HumanMessage(content=user_input)]},
        config,
        stream_mode="messages",
    ):
        if chunk.content:
            print(chunk.content, end="", flush=True)
            ai_content += chunk.content
    print()

conn.close()
