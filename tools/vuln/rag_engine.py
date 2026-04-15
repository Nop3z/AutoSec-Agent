import json
import os
from typing import Any


class VulnRAG:
    """
    轻量级漏洞知识库 RAG 引擎。
    当前实现基于本地 JSON 关键词匹配，预留向量检索接口，后续可替换为 FAISS/Chroma。
    """

    def __init__(self, kb_path: str | None = None):
        if kb_path is None:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            kb_path = os.path.join(project_root, "data", "knowledge_base", "vuln_patterns.json")
        self.kb_path = kb_path
        self.patterns = []
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.kb_path):
            return
        with open(self.kb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.patterns = data.get("patterns", [])

    def query(self, vuln_type: str) -> list[dict[str, Any]]:
        """
        根据漏洞类型查询相关知识。
        """
        results = []
        vuln_type_lower = vuln_type.lower()
        for p in self.patterns:
            if p.get("type", "").lower() == vuln_type_lower:
                results.append(p)
        return results

    def search_by_keyword(self, keyword: str) -> list[dict[str, Any]]:
        """
        基于关键词模糊匹配知识库条目。
        """
        results = []
        keyword_lower = keyword.lower()
        for p in self.patterns:
            score = 0
            text = f"{p.get('type', '')} {p.get('name', '')} {p.get('description', '')}"
            if keyword_lower in text.lower():
                score += 10
            for pat in p.get("patterns", []):
                if keyword_lower in pat.lower():
                    score += 5
            if score > 0:
                results.append({**p, "_rag_score": score})
        # 按匹配度排序
        results.sort(key=lambda x: x.get("_rag_score", 0), reverse=True)
        return results
