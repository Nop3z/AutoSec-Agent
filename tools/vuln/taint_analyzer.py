"""
污点分析模块：对规则扫描发现的候选漏洞进行参数可控性分析。
"""

import json
import os
from typing import Any

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage

from core.model import model

# 污点分析 Agent 系统提示词
TAINT_ANALYSIS_PROMPT = """
你是一位资深的汽车网络安全与嵌入式系统漏洞分析专家，专门负责进行**污点分析（Taint Analysis）**。

## 任务说明
对于规则扫描发现的可疑漏洞代码片段，你需要分析：
1. **参数来源分析**：关键参数（如 system/popen 的命令字符串、strcpy 的源字符串等）是否来自用户可控的输入
2. **数据流追踪**：参数是否经过净化处理（如长度检查、白名单过滤、编码转义等）
3. **利用可行性评估**：该漏洞在当前上下文中是否可被实际利用

## 分析维度
- **可控性（Controllability）**: 
  - `user_input` - 直接来自用户输入（命令行参数、网络数据、文件读取等）
  - `indirect` - 间接受控（如环境变量、配置文件）
  - `hardcoded` - 硬编码值，不可控
  - `unknown` - 无法从当前上下文判断

- **净化状态（Sanitization）**:
  - `none` - 无任何净化
  - `partial` - 部分净化（如长度检查但不严格）
  - `full` - 完整净化（白名单、严格转义等）
  - `unknown` - 无法判断

- **利用可能性（Exploitability）**:
  - `confirmed` - 确认可利用
  - `likely` - 很可能可利用
  - `unlikely` - 不太可能利用
  - `false_positive` - 误报，非真实漏洞

## 输出格式
请严格按照以下 JSON 格式输出分析结果（不要包含 markdown 代码块标记）：

{
  "controllability": "user_input/indirect/hardcoded/unknown",
  "sanitization": "none/partial/full/unknown",
  "exploitability": "confirmed/likely/unlikely/false_positive",
  "confidence": 0.8,
  "reasoning": "详细分析说明...",
  "attack_scenario": "如果可利用，描述攻击场景；否则说明为何不可利用",
  "recommendations": ["修复建议1", "修复建议2"]
}

## 注意事项
- 如果代码片段中参数明显是硬编码字符串（如 `system("/bin/sh")`），应标记为 false_positive
- 如果参数来自函数参数且无法判断来源，标记为 unknown
- 对于反编译代码，注意识别 IDA/Ghidra 生成的伪代码特征
- 分析要基于实际代码上下文，不要过度推测
"""

# 创建污点分析 Agent
taint_analysis_agent = create_agent(
    model,
    tools=[],
    system_prompt=TAINT_ANALYSIS_PROMPT,
)


def analyze_taint(
    finding: dict[str, Any],
    project_name: str,
    binary_name: str,
) -> dict[str, Any]:
    """
    对单个候选漏洞进行污点分析。
    
    Args:
        finding: 规则扫描发现的候选漏洞
        project_name: 项目名称
        binary_name: 二进制文件名
        
    Returns:
        包含污点分析结果的字典
    """
    # 构建分析上下文
    context = f"""
项目名称: {project_name}
二进制文件: {binary_name}
漏洞类型: {finding.get('type', 'unknown')}
严重程度: {finding.get('severity', 'unknown')}
来源: {finding.get('source', 'unknown')}
文件: {finding.get('file', 'unknown')}
行号: {finding.get('line', 0)}

代码片段:
```c
{finding.get('snippet', '')}
```

RAG 知识库信息:
{json.dumps(finding.get('rag_knowledge', {}), ensure_ascii=False, indent=2)}

请对上述代码片段进行污点分析，判断该"漏洞"是否真实可利用。
"""

    try:
        result = taint_analysis_agent.invoke({
            "messages": [HumanMessage(content=context)]
        })
        
        # 解析 Agent 返回的 JSON
        content = result["messages"][-1].content
        
        # 尝试提取 JSON（Agent 可能会用 markdown 代码块包裹）
        json_str = content
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0].strip()
        
        analysis = json.loads(json_str)
        
        # 验证必要字段
        required_fields = ["controllability", "sanitization", "exploitability", "reasoning"]
        for field in required_fields:
            if field not in analysis:
                analysis[field] = "unknown"
        
        if "confidence" not in analysis:
            analysis["confidence"] = 0.5
            
        return analysis
        
    except Exception as e:
        # 分析失败时返回未知状态
        return {
            "controllability": "unknown",
            "sanitization": "unknown", 
            "exploitability": "unknown",
            "confidence": 0.0,
            "reasoning": f"污点分析过程出错: {str(e)}",
            "attack_scenario": "无法确定",
            "recommendations": ["建议人工复核此发现"],
        }


def filter_false_positives(
    findings: list[dict[str, Any]],
    min_confidence: float = 0.3,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    根据污点分析结果过滤误报。
    
    Args:
        findings: 包含污点分析结果的发现列表
        min_confidence: 最小置信度阈值
        
    Returns:
        (确认漏洞列表, 误报/低风险列表)
    """
    confirmed = []
    false_positives = []
    
    for f in findings:
        taint = f.get("taint_analysis", {})
        exploitability = taint.get("exploitability", "unknown")
        confidence = taint.get("confidence", 0.5)
        
        # 判断逻辑
        if exploitability == "false_positive":
            false_positives.append(f)
        elif exploitability == "confirmed" and confidence >= min_confidence:
            confirmed.append(f)
        elif exploitability == "likely" and confidence >= min_confidence:
            confirmed.append(f)
        elif exploitability == "unlikely":
            false_positives.append(f)
        else:
            # 未知或低置信度，保留但标记为待复核
            f["needs_review"] = True
            confirmed.append(f)
    
    return confirmed, false_positives
