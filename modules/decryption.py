import os
import zipfile
import subprocess
from io import BytesIO
from pathlib import Path
from elftools.elf.elffile import ELFFile
from Crypto.Cipher import AES

DEX_MAGIC = b'dex\n'
KEY_LENGTH = 16

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(f"[CMD] {cmd}")
    if result.stdout:
        print("[STDOUT]", result.stdout)
    if result.stderr:
        print("[STDERR]", result.stderr)
    return result

def is_dex(data: bytes):
    return data.startswith(DEX_MAGIC)

def extract_strings(data: bytes, length=16):
    result, current = [], b""
    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) == length:
                result.append(current.decode(errors='ignore'))
            current = b''
    if len(current) == length:
        result.append(current.decode(errors='ignore'))
    return list(set(result))

def get_candidate_keys(so_path):
    keys = []
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.header.sh_type == 'SHT_PROGBITS':
                try:
                    keys += extract_strings(section.data(), KEY_LENGTH)
                except:
                    continue
    return keys

def decrypt_dex(file_path, keys):
    with open(file_path, 'rb') as f:
        encrypted = f.read()

    for key in keys:
        try:
            cipher = AES.new(key.encode(), AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted)
            if BytesIO(decrypted).read(4) == DEX_MAGIC:
                print(f"[+] 복호화 성공 (키: {key}) - {file_path}")
                return decrypted
        except:
            continue
    return None

def save_overwrite(path, data):
    with open(path, 'wb') as f:
        f.write(data)

def find_files(folder, ext):
    return [str(p) for p in Path(folder).rglob(f'*.{ext}')]

def ensure_keystore_exists(keystore_path="dummy.keystore", alias="alias"):
    if not os.path.exists(keystore_path):
        print("[*] keystore 파일이 없어 새로 생성합니다...")
        keytool_cmd = (
            f'keytool -genkey -v -keystore "{keystore_path}" '
            f'-alias {alias} -keyalg RSA -keysize 2048 -validity 10000 '
            f'-storepass 111111 -keypass 111111 -dname "CN=MobSF,O=MobSF,L=City,ST=State,C=KR"'
        )
        result = subprocess.run(keytool_cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print("[!] keystore 생성 실패:")
            print(result.stderr)
            raise Exception("keystore 생성 실패")
        print("[+] dummy.keystore 생성 완료.")

def repack_and_sign(decompiled_dir, output_dir, apk_name):
    os.makedirs(output_dir, exist_ok=True)
    unsigned_apk = os.path.join(output_dir, f"{apk_name}_unsigned.apk")
    signed_apk = os.path.join(output_dir, f"{apk_name}_dec.apk")

    build_cmd = f"apktool b \"{decompiled_dir}\" -o \"{unsigned_apk}\""
    keystore_path = "dummy.keystore"
    alias = 'alias'

    print("[*] 전체 APK 리패키징...")
    if run_cmd(build_cmd).returncode != 0:
        raise Exception("apktool 빌드 실패")

    ensure_keystore_exists(keystore_path, alias)

    sign_cmd = (
        f"jarsigner "
        f"-keystore {keystore_path} "
        f"-storepass 111111 "
        f"-keypass 111111 "
        f"-signedjar \"{signed_apk}\" "
        f"\"{unsigned_apk}\" "
        f"{alias}"
    )

    if run_cmd(sign_cmd).returncode != 0:
        raise Exception("apk 서명 실패")

    print("[+] 리패키징 및 서명 완료:", signed_apk)
    return signed_apk


def extract_nested_apks(decompiled_dir):
    nested_apks = []
    for file in Path(decompiled_dir).rglob('*.apk'):
        nested_apks.append(str(file))
    return nested_apks

def decrypt_nested_apk(nested_apk_path, shared_keys):
    print(f"\n[*] Nested APK 처리 중: {nested_apk_path}")

    nested_dir = nested_apk_path + "_decompiled"
    run_cmd(f"apktool d -s -f \"{nested_apk_path}\" -o \"{nested_dir}\"")

    dex_files = find_files(nested_dir, "dex")
    decrypted_any = False

    for dex in dex_files:
        with open(dex, 'rb') as f:
            if f.read(4) == DEX_MAGIC:
                continue
        decrypted = decrypt_dex(dex, shared_keys)
        if decrypted:
            save_overwrite(dex, decrypted)
            decrypted_any = True

    if decrypted_any:
        print(f"[*] Nested 복호화 성공 → 리패키징")
        repack_cmd = f"apktool b \"{nested_dir}\" -o \"{nested_apk_path}\""
        run_cmd(repack_cmd)
        sign_cmd = (
            f"jarsigner -keystore dummy.keystore -storepass 111111 "
            f"-keypass 111111 -signedjar \"{nested_apk_path}\" "
            f"\"{nested_apk_path}\" alias"
        )
        run_cmd(sign_cmd)
    else:
        print("[!] Nested dex 복호화 실패. 원본 유지")


def decrypt_apk(apk_path):
    original_dir = os.path.dirname(apk_path)
    apk_name = Path(apk_path).stem
    output_dir = os.path.join(original_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    decompiled_dir = os.path.join(output_dir, f"{apk_name}_decompiled")
    print("[1] apktool 디컴파일 중...")
    run_cmd(f"apktool d -s -f \"{apk_path}\" -o \"{decompiled_dir}\"")

    print("[2] .so 키 추출 중...")
    so_files = find_files(decompiled_dir, "so")
    keys = []
    for so in so_files:
        keys += get_candidate_keys(so)

    if not keys:
        print("[-] 키를 찾을 수 없음 → 복호화 생략")
        return apk_path

    print("[3] Nested APK 탐색 중...")
    nested_apks = extract_nested_apks(decompiled_dir)
    for nested in nested_apks:
        decrypt_nested_apk(nested, keys)  # keys는 메인 apk의 .so에서 추출한 공통 키

    print("[4] dex 복호화 중...")
    decrypted = False
    dex_files = find_files(decompiled_dir, "dex")
    for dex in dex_files:
        with open(dex, 'rb') as f:
            if f.read(4) == DEX_MAGIC:
                continue
        decrypted_data = decrypt_dex(dex, keys)
        if decrypted_data:
            save_overwrite(dex, decrypted_data)
            decrypted = True

    if decrypted:
        print("[5] dex 복호화 성공 → 리패키징")
        return repack_and_sign(decompiled_dir, output_dir, apk_name)
    else:
        print("[!] 복호화된 dex 없음 → 원본 사용")
        return apk_path
