# analyzer/mobsf_controller.py

import requests
from pathlib import Path
import pdfkit


def is_mobsf_alive(host: str, api_key: str) -> bool:
    """MobSF 서버 상태 확인 - /api/v1/scans 엔드포인트 사용"""
    try:
        url = f"{host}/api/v1/scans"
        headers = {"Authorization": api_key}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            print("✅ MobSF 서버 응답 정상")
            return True
        else:
            print(f"⚠ MobSF 서버 응답 상태 코드: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"❌ MobSF 서버 연결 실패: {e}")
        return False


def upload_apk(apk_path: Path, host: str, api_key: str) -> str:
    """APK 업로드 → 업로드 성공 시 해시값 반환"""
    url = f"{host}/api/v1/upload"
    headers = {"Authorization": api_key}

    with open(apk_path, "rb") as f:
        files = {
            "file": (
                apk_path.name,
                f,
                "application/octet-stream"
            )
        }
        response = requests.post(url, files=files, headers=headers)

    if response.status_code == 200:
        result = response.json()
        print(f"✅ APK 업로드 성공! 해시: {result['hash']}")
        return result["hash"]
    else:
        raise RuntimeError(f"❌ APK 업로드 실패: {response.text}")



def run_static_analysis(scan_hash: str, host: str, api_key: str):
    """MobSF에서 정적 분석 시작"""
    url = f"{host}/api/v1/scan"
    headers = {"Authorization": api_key}
    data = {"hash": scan_hash}

    # ✅ JSON이 아닌 form-data로 전송해야 함
    response = requests.post(url, data=data, headers=headers)

    if response.status_code == 200:
        print("🔍 정적 분석 완료!")
    else:
        raise RuntimeError(f"❌ 정적 분석 실패: {response.text}")

def download_pdf_report(scan_hash: str, host: str, api_key: str, output_path: Path, wkhtmltopdf_path: str):
    """PDF 형식 보고서 다운로드"""
    url = f"{host}/api/v1/download_pdf"
    headers = {"Authorization": api_key}
    data = {
        "hash": scan_hash,
        "scan_type": "apk"
    }

    print("[📄] PDF 보고서 다운로드 중...")
    config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(response.content)
        print(f"📄 PDF 보고서 저장 완료: {output_path}")
    else:
        raise RuntimeError(f"❌ PDF 다운로드 실패: {response.text}")