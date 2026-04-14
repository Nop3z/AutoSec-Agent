import os
import re

from langchain.tools import tool

from core.path_guard import get_project_dir, is_within_project


# 协议特征库：文件名/字符串 -> 协议名称
PROTO_SIGNATURES = {
    "fastdds": ["libfastrtps", "libfastdds", "FastDDS", "eProsima"],
    "mqtt": ["libpaho-mqtt", "libmosquitto", "MQTT", "paho"],
    "tls": ["libssl", "libcrypto", "openssl", "TLS", "SSL_CTX"],
    "someip": ["libvsomeip", "SOME/IP", "vsomeip"],
    "dlt": ["libdlt", "DLT", "GENIVI"],
    "protobuf": ["libprotobuf", "protobuf", "google::protobuf"],
    "grpc": ["libgrpc", "grpc", "google.rpc"],
    "coap": ["libcoap", "COAP", "coap_packet"],
}


def _scan_path(path: str) -> dict:
    """递归扫描目录，匹配协议特征。"""
    found = {}

    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = []
        for root, _, filenames in os.walk(path):
            for fn in filenames:
                files.append(os.path.join(root, fn))
    else:
        return {"error": f"invalid path: {path}"}

    for filepath in files:
        basename = os.path.basename(filepath).lower()

        # 1) 文件名匹配
        for proto, sigs in PROTO_SIGNATURES.items():
            if any(sig.lower() in basename for sig in sigs):
                found.setdefault(proto, {"files": [], "strings": []})
                found[proto]["files"].append(filepath)

        # 2) 文本/二进制字符串匹配（只读前 2MB，避免大文件卡死）
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(2 * 1024 * 1024)
            # 尝试解码为文本，忽略不可读字节
            text = chunk.decode("utf-8", "ignore")
            for proto, sigs in PROTO_SIGNATURES.items():
                for sig in sigs:
                    if re.search(re.escape(sig), text, re.IGNORECASE):
                        found.setdefault(proto, {"files": [], "strings": []})
                        if filepath not in found[proto]["files"]:
                            found[proto]["strings"].append(f"{filepath}: matched '{sig}'")
                        break
        except (OSError, PermissionError):
            continue

    return {
        "protocols": list(found.keys()),
        "details": found,
        "scanned_files": len(files),
    }


@tool
def identify_protocol(firmware_path: str, project_name: str) -> dict:
    """
    扫描固件目录，识别其中使用的通信协议（如 FastDDS、MQTT、TLS 等）。
    参数 firmware_path 为固件解压后的目录路径。
    """
    # 路径安全检查
    project_dir = get_project_dir(project_name)
    
    if not os.path.exists(firmware_path):
        return {"error": f"路径不存在: {firmware_path}"}
    
    if not is_within_project(firmware_path, project_dir):
        return {
            "error": f"路径 '{firmware_path}' 超出项目目录 '{project_dir}'，拒绝访问",
            "project_dir": project_dir,
        }
    
    if os.path.isfile(firmware_path):
        # 单文件：扫描其父目录
        return _scan_path(os.path.dirname(firmware_path))
    
    return _scan_path(firmware_path)
