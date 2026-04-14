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
    report_markdown: str | None
