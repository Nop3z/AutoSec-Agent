from typing import TypedDict, Annotated
from langgraph.graph.message import add_messages


class AutoSecState(TypedDict):
    messages: Annotated[list, add_messages]
    project_name: str
    target_path: str
    input_type: str

    # firmware
    firmware_crypto: list | None
    firmware_certs: list | None
    firmware_algo27: list | None
    firmware_chip: str | None
    firmware_cockpit: str | None

    # network
    network_topology: dict | None
    network_tps_addrs: list | None
    network_routes: list | None
    network_protocols: list | None

    # supply_chain
    oss_components: list | None

    # vuln
    vuln_findings: list | None
    vuln_scan_result: dict | None  # 完整扫描结果（包含污点分析）
    vuln_scan_complete: bool | None  # 扫描完成标记
    
    # vuln pipeline (4-agent)
    recon_data: dict | None  # 信息侦查结果
    cmd_inject_findings: dict | None  # 命令注入高危函数侦查结果
    xrefs_analysis: dict | None  # 交叉引用关系分析结果
    verification_results: dict | None  # 漏洞验证结果
    
    report_markdown: str | None
