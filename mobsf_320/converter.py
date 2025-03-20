# -*- coding: utf_8 -*-
"""Module holding the functions for converting."""

import glob
import logging
import os
import platform
import shutil
import subprocess
import threading
import stat
from pathlib import Path
from tempfile import gettempdir

from mobsf.StaticAnalyzer.tools.dex import decrypt_dex
import zipfile


from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    filename_from_path,
    find_java_binary,
    is_file_exists,
    settings_enabled,
)


logger = logging.getLogger(__name__)
# 수정된 부분

MOBSF_UPLOAD_DIR = os.path.expanduser("~/.MobSF/uploads")

def get_apk_path(apk_hash):
    """MobSF 업로드 디렉토리에서 특정 APK 파일 경로 반환"""
    apk_dir = os.path.join(MOBSF_UPLOAD_DIR, apk_hash)
    apk_files = glob.glob(os.path.join(apk_dir, "*.apk"))  # 🔥 모든 APK 검색
    if apk_files:
        return apk_files[0]  # 첫 번째 APK 반환
    else:
        logger.error(f" APK 파일을 찾을 수 없음: {apk_dir}")
        return None

def extract_nested_apk(apk_hash):
    """지정된 APK에서 Nested APK 파일을 강제로 추출"""
    apk_path = get_apk_path(apk_hash)
    if not apk_path:
        return []

    nested_apk_files = []
    extracted_path = os.path.join(MOBSF_UPLOAD_DIR, apk_hash, "nested_apks")
    os.makedirs(extracted_path, exist_ok=True)

    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            for file in zip_ref.namelist():
                if file.endswith(".apk"):
                    nested_apk_path = os.path.join(extracted_path, os.path.basename(file))
                    with open(nested_apk_path, "wb") as f:
                        f.write(zip_ref.read(file))
                    logger.info(f" Nested APK 추출 완료: {nested_apk_path}")
                    nested_apk_files.append(nested_apk_path)
    except Exception as e:
        logger.error(f" Nested APK 추출 실패: {e}")

    return nested_apk_files

def safe_rename(src, dst):
    """
    대상 파일(dst)이 존재하면 삭제 후 src를 dst로 이동.
    필요에 따라 고유한 이름 생성 로직을 추가할 수 있음.
    """
    if os.path.exists(dst):
        try:
            os.remove(dst)
            logger.info(f" 기존 파일 삭제: {dst}")
        except Exception as e:
            logger.error(f" 기존 파일 삭제 실패 ({dst}): {e}")
    os.rename(src, dst)

def extract_dex_from_nested_apk(nested_apks):
    """Nested APK 내부에서 DEX 파일을 추출"""
    dex_files = []
    for nested_apk in nested_apks:
        nested_apk_extract_dir = nested_apk.replace(".apk", "_extracted")
        os.makedirs(nested_apk_extract_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(nested_apk, 'r') as zip_ref:
                zip_ref.extractall(nested_apk_extract_dir)

            nested_dex_files = glob.glob(os.path.join(nested_apk_extract_dir, '**', '*.dex'), recursive=True)
            for dex in nested_dex_files:
                new_dex_name = f"nested_{os.path.basename(nested_apk)}_{os.path.basename(dex)}"
                new_dex_path = os.path.join(nested_apk_extract_dir, new_dex_name)
                try:
                    safe_rename(dex, new_dex_path)
                    dex_files.append(new_dex_path)
                    logger.info(f" Nested DEX 추출 완료: {new_dex_path}")
                except Exception as e:
                    logger.error(f" Nested APK DEX 추출 실패: {e}")
        except Exception as e:
            logger.error(f" Nested APK DEX 추출 실패: {e}")

    return dex_files

def get_dex_files(apk_hash):
    """APK 및 Nested APK에서 DEX 파일을 찾아서 분석"""
    dex_files = []
    decrypted_dex_files = []

    apk_path = get_apk_path(apk_hash)
    if not apk_path:
        return []

    extracted_apk_dir = os.path.join(MOBSF_UPLOAD_DIR, apk_hash, "extracted_apks")
    os.makedirs(extracted_apk_dir, exist_ok=True)

    # ✅ Nested APK 강제 추출
    nested_apks = extract_nested_apk(apk_hash)

    # ✅ APK 내부 DEX 추출
    dex_files.extend(glob.glob(os.path.join(MOBSF_UPLOAD_DIR, apk_hash, "*.dex")))

    # ✅ Nested APK 내부 DEX 추출
    nested_dex_files = extract_dex_from_nested_apk(nested_apks)
    dex_files.extend(nested_dex_files)

    logger.info(f" 최종 DEX 파일 목록: {dex_files}")

    # ✅ DEX 복호화 처리
    for dex in dex_files:
        logger.info(f" Found DEX: {dex}")

        if "kill-classes.dex" in dex or "kill-classes2.dex" in dex:
            logger.info(f" 암호화된 DEX 발견: {dex}, 복호화 진행 중...")
            decrypted_dex = decrypt_dex(dex)

            if decrypted_dex:
                decrypted_dex_path = dex.replace(".dex", "-decrypted.dex")
                os.rename(decrypted_dex, decrypted_dex_path)
                decrypted_dex_files.append(decrypted_dex_path)
                logger.info(f" 복호화 완료: {decrypted_dex_path}")

                # ✅ 원본 `kill-classes.dex` 삭제
                os.remove(dex)
                logger.info(f" 원본 DEX 삭제: {dex}")
            else:
                logger.warning(f" 복호화 실패: {dex} (올바른 DEX 파일이 아님)")
        else:
            decrypted_dex_files.append(dex)

    logger.info(f" 최종 분석 대상 DEX 파일 목록: {decrypted_dex_files}")
    return decrypted_dex_files





'''
def get_dex_files(app_dir):
    """DEX 파일을 찾고 암호화된 경우 자동 복호화"""
    glob_pattern = os.path.join(app_dir, '*.dex')
    dex_files = glob.glob(glob_pattern)
    decrypted_dex_files = []

    for dex in dex_files:
        logger.info(f"🔍 Found DEX: {dex}")

        # 🔥 `kill-classes.dex`가 암호화된 경우 복호화
        if "kill-classes.dex" in dex:
            logger.info(f"🔓 암호화된 DEX 발견: {dex}, 복호화 진행 중...")
            decrypted_dex = decrypt_dex(dex)
            if decrypted_dex:
                decrypted_dex_path = dex.replace(".dex", "-decrypted.dex")
                os.rename(decrypted_dex, decrypted_dex_path)  # ✅ 복호화된 파일 유지
                decrypted_dex_files.append(decrypted_dex_path)
                logger.info(f"✅ 복호화 완료: {decrypted_dex_path}")
            else:
                logger.warning(f"❌ 복호화 실패: {dex} (올바른 DEX 파일이 아님)")
        else:
            decrypted_dex_files.append(dex)

    logger.info(f"🔍 최종 DEX 파일 목록: {decrypted_dex_files}")
    return decrypted_dex_files
'''



'''def get_dex_files(app_dir):
    """Get all Dex Files for analysis."""
    glob_pattern = app_dir + '*.dex'
    return glob.glob(glob_pattern)
'''

def dex_2_smali(checksum, app_dir, tools_dir):
    """Run dex2smali."""
    try:
        if not settings_enabled('DEX2SMALI_ENABLED'):
            return
        msg = 'Converting DEX to Smali'
        logger.info(msg)
        append_scan_status(checksum, msg)
        dexes = get_dex_files(app_dir)
        for dex_path in dexes:
            try:
                logger.info('Converting %s to Smali Code',
                            filename_from_path(dex_path))
                if (len(settings.BACKSMALI_BINARY) > 0
                        and is_file_exists(settings.BACKSMALI_BINARY)):
                    bs_path = settings.BACKSMALI_BINARY
                else:
                    bs_path = os.path.join(tools_dir, 'baksmali-3.0.8-dev-fat.jar')
                output = os.path.join(app_dir, 'smali_source/')
                smali = [
                    find_java_binary(),
                    '-jar',
                    bs_path,
                    'd',
                    dex_path,
                    '-o',
                    output,
                ]
                trd = threading.Thread(target=subprocess.call, args=(smali,))
                trd.daemon = True
                trd.start()
            except Exception:
                # Fixes a bug #2014
                pass
    except Exception as exp:
        msg = 'Failed to convert DEX to Smali'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def apk_2_java(checksum, app_path, app_dir, dwd_tools_dir):
    """Run JADX to decompile APK or all DEX files to Java source code."""
    try:
        jadx_version = '1.5.0'
        jadx_base_path = Path(dwd_tools_dir) / 'jadx' / f'jadx-{jadx_version}' / 'bin'
        output_dir = Path(app_dir) / 'java_source'

        msg = 'Decompiling APK to Java with JADX'
        logger.info(msg)
        append_scan_status(checksum, msg)

        # Clean output directory if it exists
        if output_dir.exists():
            shutil.rmtree(output_dir, ignore_errors=True)

        # Determine JADX executable path
        if (len(settings.JADX_BINARY) > 0
                and is_file_exists(settings.JADX_BINARY)):
            jadx = Path(settings.JADX_BINARY)
        elif platform.system() == 'Windows':
            jadx = jadx_base_path / 'jadx.bat'
        else:
            jadx = jadx_base_path / 'jadx'

        # Ensure JADX has execute permissions
        if not os.access(str(jadx), os.X_OK):
            os.chmod(str(jadx), stat.S_IEXEC)

        # Prepare the base arguments for JADX
        def run_jadx(arguments):
            """Run JADX command with the specified arguments."""
            with open(os.devnull, 'w') as fnull:
                return subprocess.run(
                    arguments,
                    stdout=fnull,
                    stderr=subprocess.STDOUT,
                    timeout=settings.JADX_TIMEOUT)

        # First attempt to decompile APK
        args = [
            str(jadx), '-ds', str(output_dir),
            '-q', '-r', '--show-bad-code', app_path]
        result = run_jadx(args)
        if result.returncode == 0:
            return  # Success

        # If APK decompilation fails, attempt to decompile all DEX files recursively
        msg = 'Decompiling with JADX failed, attempting on all DEX files'
        logger.warning(msg)
        append_scan_status(checksum, msg)

        dex_files = Path(app_path).parent.rglob('*.dex')
        decompile_failed = False

        for dex_file in dex_files:
            msg = f'Decompiling {dex_file.name} with JADX'
            logger.info(msg)
            append_scan_status(checksum, msg)

            # Update argument to point to the current DEX file
            args[-1] = str(dex_file)
            result_dex = run_jadx(args)

            if result_dex.returncode != 0:
                decompile_failed = True
                msg = f'Decompiling with JADX failed for {dex_file.name}'
                logger.error(msg)
                append_scan_status(checksum, msg)

        if decompile_failed:
            msg = 'Some DEX files failed to decompile'
            logger.error(msg)
            append_scan_status(checksum, msg)

    except subprocess.TimeoutExpired as exp:
        msg = 'Decompiling with JADX timed out'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    except Exception as exp:
        msg = 'Decompiling with JADX failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def run_apktool(app_path, app_dir, tools_dir):
    """Get readable AndroidManifest.xml from APK."""
    try:
        if (len(settings.APKTOOL_BINARY) > 0
                and Path(settings.APKTOOL_BINARY).exists()):
            apktool_path = Path(settings.APKTOOL_BINARY)
        else:
            apktool_path = tools_dir / 'apktool_2.10.0.jar'

        # Prepare output directory and manifest file paths
        output_dir = app_dir / 'apktool_out'
        # Run apktool to extract AndroidManifest.xml
        args = [find_java_binary(),
                '-jar',
                '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
                str(apktool_path),
                '--match-original',
                '--frame-path',
                gettempdir(),
                '-f', '-s', 'd',
                str(app_path),
                '-o',
                str(output_dir)]
        logger.info('Converting AXML to XML with apktool')
        with open(os.devnull, 'w') as fnull:
            subprocess.run(
                args,
                stdout=fnull,
                stderr=subprocess.STDOUT,
                timeout=settings.JADX_TIMEOUT)
    except Exception:
        logger.warning('apktool failed to extract AndroidManifest.xml')
