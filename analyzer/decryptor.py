# analyzer/decryptor.py (수정 버전)

import os
import shutil
import subprocess
from pathlib import Path
from io import BytesIO
from typing import List
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from elftools.elf.elffile import ELFFile

DEX_MAGIC = b'dex\n035\x00'
BLOCK_SIZE = AES.block_size


def is_valid_dex_header(data: bytes) -> bool:
    return data.startswith(DEX_MAGIC)

def extract_strings(data: bytes, length: int = 16) -> List[str]:
    result, current = [], b""
    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) == length:
                result.append(current.decode(errors='ignore'))
            current = b""
    if len(current) == length:
        result.append(current.decode(errors='ignore'))
    return list(set(result))

def extract_keys_from_so(so_path: Path) -> List[str]:
    keys = []
    try:
        with open(so_path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section.header.sh_type == 'SHT_PROGBITS':
                    try:
                        keys += extract_strings(section.data())
                    except Exception:
                        continue
    except Exception as e:
        print(f"[!] 키 추출 오류 ({so_path.name}): {e}")
    return keys

def decrypt_dex_file(file_path: Path, keys: List[str]):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if is_valid_dex_header(data):
            print(f"⚠️ 이미 복호화된 DEX (패스): {file_path.name}")
            return

        if len(data) % BLOCK_SIZE != 0:
            print(f"⚠️ 블록 정렬 안됨, 복호화 생략: {file_path.name}")
            return

        for key in keys:
            try:
                cipher = AES.new(key.encode(), AES.MODE_ECB)
                decrypted = cipher.decrypt(data)
                decrypted_io = BytesIO(decrypted)
                magic = decrypted_io.read(8)

                if is_valid_dex_header(magic):
                    decrypted_io.seek(0)
                    try:
                        final_data = unpad(decrypted_io.read(), BLOCK_SIZE)
                    except ValueError:
                        decrypted_io.seek(0)
                        final_data = decrypted_io.read()

                    with open(file_path, "wb") as f:
                        f.write(final_data)
                    print(f"✅ 복호화 성공 ({key}): {file_path.name}")
                    return
            except Exception:
                continue

        print(f"❌ 복호화 실패: {file_path.name}")

    except Exception as e:
        print(f"❌ 복호화 오류 ({file_path.name}): {e}")

def decrypt_all_dex_in_dir(directory: Path, keys: List[str]):
    for dex in directory.glob("**/*.dex"):
        decrypt_dex_file(dex, keys)

def extract_nested_apks(directory: Path) -> List[Path]:
    nested_apks = []
    assets_dir = directory / "assets"
    if assets_dir.exists():
        nested_apks.extend(assets_dir.glob("*.apk"))
    return nested_apks

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(f"[CMD] {cmd}")
    if result.stdout:
        print("[STDOUT]", result.stdout)
    if result.stderr:
        print("[STDERR]", result.stderr)
    return result

''' # 이 코드를 실행했을 때에는 Build 폴더 안 Dex 파일도 같이 분석됨
def decrypt_nested_apk(nested_apk_path: Path, keys: List[str]):
    output_dir = nested_apk_path.parent / nested_apk_path.stem
    run_cmd(f"apktool d -s -f \"{nested_apk_path}\" -o \"{output_dir}\"")
    decrypt_all_dex_in_dir(output_dir, keys)
    rebuilt_apk = nested_apk_path.parent / nested_apk_path.name
    run_cmd(f"apktool b \"{output_dir}\" -o \"{rebuilt_apk}\"")
    print(f"🔄 nested APK 리패키징 완료: {rebuilt_apk}")'
'''

def decrypt_nested_apk(nested_apk_path: Path, keys: list[str]):
    """
    nested APK를 디컴파일 → DEX 복호화 → 리패키징 → 덮어쓰기
    리패키징 후 생성된 build/apk 내부 DEX 삭제도 포함
    """
    output_dir = nested_apk_path.parent / nested_apk_path.stem

    # 1. 디컴파일
    cmd = f"apktool d -f -s -o \"{output_dir}\" \"{nested_apk_path}\""
    result = os.system(cmd)
    if result != 0:
        print(f"❌ apktool 디컴파일 실패: {nested_apk_path}")
        return

    # 2. DEX 복호화
    decrypt_all_dex_in_dir(output_dir, keys)

    # 3. 리패키징
    rebuilt_apk = nested_apk_path.parent / nested_apk_path.name
    rebuild_cmd = f"apktool b \"{output_dir}\" -o \"{rebuilt_apk}\""
    result = os.system(rebuild_cmd)
    if result != 0:
        print(f"❌ apktool 리패키징 실패: {nested_apk_path}")
        return

    print(f"🔄 nested APK 리패키징 완료: {rebuilt_apk}")

    # 4. 최종적으로 output_dir/build/apk 내부 DEX 제거
    build_dir = output_dir / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
        print(f"🧹 리패키징 후 build 디렉토리 삭제 완료: {build_dir}")





def decrypt_apk(apk_dir: str):
    apk_path = Path(apk_dir)
    print(f"🔍 DEX 복호화 시작: {apk_path}")

    so_files = list(apk_path.glob("**/*.so"))
    keys = []
    for so in so_files:
        keys += extract_keys_from_so(so)
    keys = list(set(keys))

    if not keys:
        print("⚠️ 사용 가능한 키를 찾지 못함 → 복호화 생략")
        return

    print(f"🔑 추출된 키 후보 수: {len(keys)}")
    decrypt_all_dex_in_dir(apk_path, keys)

    print(f"📦 Nested APK 검색 중...")
    nested_apks = extract_nested_apks(apk_path)
    for nested_apk in nested_apks:
        print(f"🔍 Nested APK 발견: {nested_apk.name}")
        decrypt_nested_apk(nested_apk, keys)

    print("🎉 전체 DEX 복호화 완료")