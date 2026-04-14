import os
import re

from langchain.tools import tool

from core.path_guard import get_project_dir, is_within_project


# 加密算法特征：函数名/字符串 -> 算法名称
CRYPTO_SIGNATURES = {
    "AES": ["AES_set_encrypt_key", "AES_encrypt", "AES_decrypt", "aes_init", "Rijndael"],
    "RSA": ["RSA_generate_key_ex", "RSA_public_encrypt", "RSA_sign", "rsa_"],
    "DES": ["DES_set_key", "DES_ncbc_encrypt", "DES_ecb_encrypt"],
    "SM4": ["SM4_encrypt", "sm4_crypt_ecb", "sm4_setkey"],
    "SHA256": ["SHA256_Init", "sha256_update", "SHA256_Final"],
    "MD5": ["MD5_Init", "md5_update", "MD5_Final"],
    "SHA1": ["SHA1_Init", "sha1_update", "SHA1_Final"],
    "ECDSA": ["ECDSA_sign", "ECDSA_verify", "ecdsa_"],
    "HMAC": ["HMAC_Init_ex", "hmac_"],
    "PBKDF2": ["PKCS5_PBKDF2_HMAC"],
    "Blowfish": ["BF_set_key", "BF_encrypt"],
    "RC4": ["RC4_set_key", "RC4"],
}


def _scan_crypto(path: str) -> dict:
    found = {}
    scanned = 0

    for root, _, files in os.walk(path):
        for f in files:
            filepath = os.path.join(root, f)
            scanned += 1
            try:
                with open(filepath, "rb") as fp:
                    chunk = fp.read(2 * 1024 * 1024)
                text = chunk.decode("utf-8", "ignore")
                for algo, sigs in CRYPTO_SIGNATURES.items():
                    matched = False
                    for sig in sigs:
                        if re.search(re.escape(sig), text, re.IGNORECASE):
                            found.setdefault(algo, {"files": set(), "strings": []})
                            found[algo]["files"].add(filepath)
                            found[algo]["strings"].append(f"{filepath}: matched '{sig}'")
                            matched = True
                            break
            except (OSError, PermissionError):
                continue

    # 把 set 转成 list 方便序列化
    for algo in found:
        found[algo]["files"] = list(found[algo]["files"])

    return {
        "algorithms": list(found.keys()),
        "details": found,
        "scanned_files": scanned,
    }


@tool
def detect_crypto(firmware_path: str, project_name: str) -> dict:
    """
    扫描固件目录或文件，识别其中使用的加密算法（如 AES、RSA、DES、SM4、SHA256 等）。
    参数 firmware_path 为固件解压后的目录路径或单个文件路径。
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
        # 单文件：包装成统一结果
        result = _scan_crypto(os.path.dirname(firmware_path))
        # 只保留该文件相关结果
        filtered = {}
        for algo, data in result.get("details", {}).items():
            hits = [s for s in data["strings"] if firmware_path in s]
            if hits:
                filtered[algo] = {"files": [firmware_path], "strings": hits}
        return {
            "algorithms": list(filtered.keys()),
            "details": filtered,
            "scanned_files": 1,
        }
    return _scan_crypto(firmware_path)
