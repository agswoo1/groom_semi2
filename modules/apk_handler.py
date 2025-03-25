import os
import shutil

def copy_apk(original_apk_path):
    """APK 파일을 output 디렉토리로 복사."""
    if not os.path.isfile(original_apk_path):
        raise FileNotFoundError(f"[!] 지정한 APK 파일이 존재하지 않습니다: {original_apk_path}")

    base_dir = os.path.dirname(original_apk_path)
    output_dir = os.path.join(base_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    copied_apk_path = os.path.join(output_dir, os.path.basename(original_apk_path))
    shutil.copy2(original_apk_path, copied_apk_path)

    print(f"[+] 복사된 APK 경로: {copied_apk_path}")
    return copied_apk_path


def delete_temp_apk(copied_apk_path):
    base_dir = os.path.dirname(copied_apk_path)
    base_name = os.path.splitext(os.path.basename(copied_apk_path))[0]
    temp_targets = [
        copied_apk_path,
        os.path.join(base_dir, base_name + ".zip"),
        os.path.join(base_dir, "original_apk"),
        os.path.join(base_dir, "decrypt_apk"),
        os.path.join(base_dir, "apktool.yml"),
        os.path.join(base_dir, "build"),
        os.path.join(base_dir, "dist"),
        os.path.join(base_dir, f"{base_name}.keystore"),
    ]

    print(f"[+] 임시 파일 삭제 시작...")

    for path in temp_targets:
        try:
            if os.path.isfile(path):
                os.remove(path)
                print(f"[삭제됨] 파일: {path}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                print(f"[삭제됨] 폴더: {path}")
        except Exception as e:
            print(f"[!] 삭제 실패: {path} -> {e}")

    print("[+] 임시 파일 정리 완료!")
