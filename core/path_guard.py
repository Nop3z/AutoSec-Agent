import os
from typing import Optional


def get_project_dir(project_name: str) -> str:
    """获取项目的绝对路径"""
    return os.path.abspath(os.path.join("data/outputs", project_name))


def is_within_project(path: str, project_dir: str) -> bool:
    """
    检查路径是否在项目目录内（防止目录遍历攻击）
    """
    real_path = os.path.realpath(path)
    real_project = os.path.realpath(project_dir)
    # 确保路径以项目目录开头，或者是项目目录本身
    return real_path.startswith(real_project + os.sep) or real_path == real_project


def sanitize_path(user_path: str, project_dir: str) -> Optional[str]:
    """
    净化用户输入的路径，确保其在项目目录内。
    返回安全路径，或 None（如果非法）。
    """
    # 1. 去除 .. 等路径遍历
    normalized = os.path.normpath(user_path)
    
    # 2. 如果是相对路径，基于项目目录解析
    if not os.path.isabs(normalized):
        full_path = os.path.join(project_dir, normalized)
    else:
        full_path = normalized
    
    # 3. 检查是否在项目目录内
    if not is_within_project(full_path, project_dir):
        return None
    
    return full_path


def ensure_project_path(func):
    """
    装饰器：确保 Tool 函数的 path 参数在项目目录内。
    要求被装饰函数第一个参数是 path，且 state 中有 project_name。
    """
    def wrapper(*args, **kwargs):
        # 尝试从 kwargs 或 args 获取 path 和 project_name
        path = kwargs.get("firmware_path") or kwargs.get("path") or (args[0] if args else None)
        project_name = kwargs.get("project_name")
        
        # 如果没有 project_name，尝试从 state 参数获取
        if not project_name:
            state = kwargs.get("state")
            if state and isinstance(state, dict):
                project_name = state.get("project_name")
        
        if not path or not project_name:
            return {"error": "缺少路径或项目名参数"}
        
        project_dir = get_project_dir(project_name)
        safe_path = sanitize_path(path, project_dir)
        
        if safe_path is None:
            return {
                "error": f"路径 '{path}' 超出项目目录 '{project_dir}'，拒绝访问",
                "project_dir": project_dir,
            }
        
        # 替换为安全路径
        if "firmware_path" in kwargs:
            kwargs["firmware_path"] = safe_path
        elif "path" in kwargs:
            kwargs["path"] = safe_path
        elif args:
            args = (safe_path,) + args[1:]
        
        return func(*args, **kwargs)
    
    return wrapper
