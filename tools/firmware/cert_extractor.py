import os
import re
import hashlib

from langchain.tools import tool

from core.path_guard import get_project_dir, is_within_project


# 证书和密钥的 PEM 格式正则模式
CERT_PATTERNS = {
    "certificate": (
        rb"-----BEGIN CERTIFICATE-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END CERTIFICATE-----\r?\n?"
    ),
    "rsa_private_key": (
        rb"-----BEGIN RSA PRIVATE KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END RSA PRIVATE KEY-----\r?\n?"
    ),
    "private_key": (
        rb"-----BEGIN PRIVATE KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END PRIVATE KEY-----\r?\n?"
    ),
    "ec_private_key": (
        rb"-----BEGIN EC PRIVATE KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END EC PRIVATE KEY-----\r?\n?"
    ),
    "encrypted_private_key": (
        rb"-----BEGIN ENCRYPTED PRIVATE KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END ENCRYPTED PRIVATE KEY-----\r?\n?"
    ),
    "public_key": (
        rb"-----BEGIN PUBLIC KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END PUBLIC KEY-----\r?\n?"
    ),
    "rsa_public_key": (
        rb"-----BEGIN RSA PUBLIC KEY-----\r?\n"
        rb"[A-Za-z0-9+/=\r\n]+"
        rb"-----END RSA PUBLIC KEY-----\r?\n?"
    ),
}

# DER 格式证书魔数 (X.509 SEQUENCE)
DER_CERT_MAGIC = b"\x30\x82"


def _extract_from_binary(filepath: str, cert_dir: str, source_name: str) -> list[dict]:
    """
    从二进制文件中提取嵌入的证书和密钥。
    提取的内容保存到 {cert_dir}/{source_name}/ 目录下。
    """
    extracted = []
    
    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except (OSError, IOError):
        return extracted
    
    # 创建子目录（按来源二进制文件命名）
    target_dir = os.path.join(cert_dir, source_name)
    os.makedirs(target_dir, exist_ok=True)
    
    # 提取各种 PEM 格式
    for cert_type, pattern in CERT_PATTERNS.items():
        for match in re.finditer(pattern, content):
            pem_data = match.group(0)
            
            # 计算哈希作为文件名（避免重复）
            file_hash = hashlib.sha256(pem_data).hexdigest()[:16]
            filename = f"{cert_type}_{file_hash}.pem"
            filepath_out = os.path.join(target_dir, filename)
            
            # 避免重复写入相同内容
            if os.path.exists(filepath_out):
                continue
                
            with open(filepath_out, "wb") as f:
                f.write(pem_data)
            
            extracted.append({
                "type": cert_type,
                "source": filepath,
                "saved_to": filepath_out,
                "size": len(pem_data),
            })
    
    # 提取 DER 格式证书（简化版：找 X.509 SEQUENCE 结构）
    # 实际 DER 解析很复杂，这里用启发式方法找可能的证书
    der_extracted = _extract_der_certs(content, target_dir, filepath)
    extracted.extend(der_extracted)
    
    return extracted


def _extract_der_certs(content: bytes, target_dir: str, source_path: str) -> list[dict]:
    """
    启发式提取 DER 格式证书。
    找 0x30 0x82 开头的 ASN.1 SEQUENCE，尝试解析长度并提取。
    """
    extracted = []
    
    # 找所有可能的 DER SEQUENCE 起点
    for match in re.finditer(rb"\x30\x82[\x00-\xff]{2}", content):
        start = match.start()
        
        # 尝试读取长度（2字节，大端序）
        try:
            length = int.from_bytes(content[start+2:start+4], "big")
            end = start + 4 + length
            
            # 合理性检查：证书通常在 200 字节到 16KB 之间
            if 200 < length < 16384 and end <= len(content):
                der_data = content[start:end]
                
                # 简单验证：X.509 证书应该包含某些 OID 特征
                # 比如 2.5.4.3 (commonName) 或 1.2.840.113549.1.1.1 (rsaEncryption)
                if b"\x06\x03\x55\x04\x03" in der_data or b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der_data:
                    file_hash = hashlib.sha256(der_data).hexdigest()[:16]
                    filename = f"cert_der_{file_hash}.der"
                    filepath_out = os.path.join(target_dir, filename)
                    
                    if os.path.exists(filepath_out):
                        continue
                    
                    with open(filepath_out, "wb") as f:
                        f.write(der_data)
                    
                    extracted.append({
                        "type": "der_certificate",
                        "source": source_path,
                        "saved_to": filepath_out,
                        "size": len(der_data),
                    })
        except (IndexError, ValueError):
            continue
    
    return extracted


def _copy_standalone_certs(filepath: str, cert_dir: str) -> list[dict]:
    """
    复制独立的证书文件到 Certificate/ 目录下。
    支持的扩展名：.pem, .crt, .cer, .key, .p12, .pfx, .der
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in (".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".der"):
        return []
    
    # 检查文件内容是否像证书（避免误报）
    try:
        with open(filepath, "rb") as f:
            header = f.read(100)
        
        # PEM 格式检查
        is_pem = b"-----BEGIN" in header
        # DER 格式检查
        is_der = header.startswith(b"\x30\x82")
        
        if not (is_pem or is_der):
            return []
    except (OSError, IOError):
        return []
    
    # 复制到 Certificate/ 根目录
    filename = os.path.basename(filepath)
    # 如果重名，加哈希区分
    target_path = os.path.join(cert_dir, filename)
    if os.path.exists(target_path):
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()[:8]
        name, ext = os.path.splitext(filename)
        target_path = os.path.join(cert_dir, f"{name}_{file_hash}{ext}")
    
    try:
        with open(filepath, "rb") as src, open(target_path, "wb") as dst:
            dst.write(src.read())
        
        return [{
            "type": "standalone_cert",
            "source": filepath,
            "saved_to": target_path,
            "size": os.path.getsize(target_path),
        }]
    except (OSError, IOError):
        return []


@tool
def extract_certificates(firmware_path: str, project_name: str) -> dict:
    """
    从固件目录中提取证书和密钥。
    
    - 独立证书文件（.pem, .crt 等）直接复制到 Certificate/
    - 嵌入在二进制文件中的证书提取到 Certificate/{二进制文件名}/
    
    参数:
        firmware_path: 固件解压后的目录路径（通常是 extractions/）
        project_name: 项目名称
    
    返回:
        提取的证书列表、保存位置、统计信息
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
    
    # 创建 Certificate 目录
    cert_dir = os.path.join(project_dir, "Certificate")
    os.makedirs(cert_dir, exist_ok=True)
    
    standalone_certs = []
    embedded_certs = []
    scanned_files = 0
    
    # 遍历所有文件
    for root, _, files in os.walk(firmware_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            scanned_files += 1
            
            # 1. 处理独立证书文件
            standalone = _copy_standalone_certs(filepath, cert_dir)
            if standalone:
                standalone_certs.extend(standalone)
                continue  # 是独立证书，不需要再扫描嵌入内容
            
            # 2. 从二进制文件中提取嵌入证书
            # 跳过太大的文件（> 50MB），避免内存问题
            try:
                size = os.path.getsize(filepath)
                if size > 50 * 1024 * 1024:
                    continue
            except OSError:
                continue
            
            source_name = os.path.splitext(filename)[0]
            embedded = _extract_from_binary(filepath, cert_dir, source_name)
            embedded_certs.extend(embedded)
    
    # 清理空目录（如果没有提取到嵌入证书）
    for item in os.listdir(cert_dir):
        item_path = os.path.join(cert_dir, item)
        if os.path.isdir(item_path):
            # 检查是否为空
            if not any(os.scandir(item_path)):
                os.rmdir(item_path)
    
    return {
        "cert_dir": cert_dir,
        "scanned_files": scanned_files,
        "standalone_certs": standalone_certs,
        "embedded_certs": embedded_certs,
        "total_extracted": len(standalone_certs) + len(embedded_certs),
        "standalone_count": len(standalone_certs),
        "embedded_count": len(embedded_certs),
    }
