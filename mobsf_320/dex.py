# -*- coding: utf-8 -*-
"""DEX Decryption Module"""

import os
from Crypto.Cipher import AES
import logging
from Crypto.Util.Padding import unpad

logger = logging.getLogger(__name__)

AES_KEY = b"dbcdcfghijklmaop"

def is_valid_dex(dex_path):
    """파일이 올바른 DEX 형식인지 확인"""
    try:
        with open(dex_path, "rb") as f:
            header = f.read(8)
        return header == b"dex\n035\x00"  # ✅ DEX 파일 헤더 확인
    except Exception as e:
        logger.error(f"DEX 형식 확인 중 오류 발생: {e}")
        return False

def decrypt_dex(enc_file_path):
    """암호화된 DEX 파일을 복호화하는 함수"""
    try:
        with open(enc_file_path, "rb") as f:
            encrypted_data = f.read()

        file_size = len(encrypted_data)
        block_remainder = file_size % 16
        logger.info(f" 파일 크기: {file_size} 바이트")
        logger.info(f" 16바이트 정렬 여부 (나머지): {block_remainder}")

        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_data = decrypted_data.rstrip(b"\x00")  # ✅ NULL 패딩 제거

        output_path = enc_file_path.replace(".dex", "-decrypted.dex")
        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        if is_valid_dex(output_path):
            logger.info(f" 복호화된 DEX 파일이 정상적인 DEX 형식임: {output_path}")
        else:
            logger.warning(f"⚠️ 복호화된 파일이 DEX 형식이 아님! {output_path}")

        return output_path
    except Exception as e:
        logger.error(f" DEX 복호화 중 오류 발생: {e}")
        return None
