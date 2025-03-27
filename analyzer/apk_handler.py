# analyzer/apk_handler.py

import shutil
import subprocess
from pathlib import Path


def copy_apk(src_path: str) -> Path:
    """s1.apk → s2.apk 복사"""
    src = Path(src_path)
    dest = src.parent / f"{src.stem}_copy.apk"
    shutil.copy(src, dest)
    print(f"📁 APK 복사 완료: {dest}")
    return dest


def decompile_apk(apk_path: Path) -> Path:
    """apktool로 APK 디컴파일"""
    output_dir = apk_path.parent / apk_path.stem
    cmd = f"apktool d -f -s -o \"{output_dir}\" \"{apk_path}\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ 디컴파일 실패: {result.stderr}")
    print(f"📦 디컴파일 완료: {output_dir}")
    return output_dir


def rebuild_apk(decompiled_path: Path, output_path: Path):
    """apktool b로 디컴파일 결과 재패키징"""
    cmd = f"apktool b \"{decompiled_path}\" -o \"{output_path}\""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ 리패키징 실패: {result.stderr}")
    print(f"📦 APK 리패키징 완료: {output_path}")


def sign_apk(apk_path: Path, signing_config: dict):
    """apksigner로 APK 서명"""
    apksigner = signing_config.get("apksigner_path", "apksigner")
    cmd = (
        f"\"{apksigner}\" sign "
        f"--ks \"{signing_config['keystore']}\" "
        f"--ks-key-alias {signing_config['alias']} "
        f"--ks-pass pass:{signing_config['storepass']} "
        f"--key-pass pass:{signing_config['keypass']} "
        f"\"{apk_path}\""
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ apksigner 서명 실패: {result.stderr}")
    print(f"🔏 apksigner로 APK 서명 완료: {apk_path}")


def delete_temp_apk(apk_path: Path):
    """복사된 APK 및 관련 파일/디렉토리 삭제"""
    try:
        if apk_path.exists():
            apk_path.unlink()
            print(f"🧹 APK 삭제 완료: {apk_path}")
        
        idsig_file = apk_path.with_suffix(apk_path.suffix + ".idsig")
        if idsig_file.exists():
            idsig_file.unlink()
            print(f"🧹 .idsig 서명파일 삭제 완료: {idsig_file}")

        decompiled_dir = apk_path.parent / apk_path.stem
        if decompiled_dir.exists() and decompiled_dir.is_dir():
            shutil.rmtree(decompiled_dir)
            print(f"🧹 디컴파일 폴더 삭제 완료: {decompiled_dir}")

    except Exception as e:
        print(f"⚠️ 정리 중 오류 발생: {e}")
