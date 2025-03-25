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
    """복사한 APK 파일을 삭제 (원본은 그대로 유지)."""
    if os.path.isfile(copied_apk_path):
        os.remove(copied_apk_path)
        print(f"[+] 임시 APK 삭제 완료: {copied_apk_path}")
    else:
        print(f"[!] 삭제할 APK를 찾을 수 없습니다: {copied_apk_path}")
