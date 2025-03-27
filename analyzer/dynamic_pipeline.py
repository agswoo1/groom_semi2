import subprocess
import threading
import time
import frida
import sys
import json
from pathlib import Path
from analyzer.mobsf_controller import upload_apk
from analyzer.config_loader import load_config
import requests
from analyzer.mobsf_controller import run_static_analysis  # 추가

def launch_app(package_name: str):
    print(f"[*] Launching app: {package_name}")
    result = subprocess.run([
        "adb", "shell", "monkey", "-p", package_name,
        "-c", "android.intent.category.LAUNCHER", "1"
    ], capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] 앱 실행 실패:", result.stderr)
    else:
        print("[+] 앱 실행 성공")

def inject_frida_script(app_name: str, frida_script_path: str):
    injected_pids = set()
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        print("[!] USB 장치 탐색 실패:", e)
        return

    def monitor():
        while True:
            try:
                processes = device.enumerate_processes()
                for process in processes:
                    if app_name.lower() in process.name.lower() and process.pid not in injected_pids:
                        print(f"[+] 대상 프로세스 발견: {process.name} (PID: {process.pid})")
                        session = device.attach(process.pid)
                        with open(frida_script_path, "r") as f:
                            script = session.create_script(f.read())
                        script.on("message", lambda msg, data: print("[Frida]", msg))
                        script.load()
                        injected_pids.add(process.pid)
                        print(f"[+] Frida 스크립트 주입 성공: PID {process.pid}")
            except Exception as e:
                print("[!] 모니터링 중 오류:", e)
            time.sleep(3)

    threading.Thread(target=monitor, daemon=True).start()

def start_dynamic_analysis(scan_hash: str, host: str, api_key: str):
    url = f"{host}/api/v1/dynamic/start_analysis"
    headers = {"Authorization": api_key}
    data = {"hash": scan_hash, "re_install": 1, "install": 1}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        print("🚀 동적 분석 시작 완료!")
        return response.json()
    else:
        raise RuntimeError(f"❌ 동적 분석 시작 실패: {response.text}")

def get_dynamic_report(scan_hash: str, host: str, api_key: str, output_path: Path):
    """동적 분석 리포트를 가져와 JSON 파일로 저장"""
    url = f"{host}/api/v1/dynamic/report_json"
    headers = {"Authorization": api_key}
    data = {"hash": scan_hash}

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        report = response.json()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"📄 동적 분석 보고서 저장 완료: {output_path}")
        return report
    else:
        raise RuntimeError(f"❌ 동적 분석 보고서 조회 실패: {response.text}")

def stop_dynamic_analysis(scan_hash: str, host: str, api_key: str):
    url = f"{host}/api/v1/dynamic/stop_analysis"
    headers = {"Authorization": api_key}
    data = {"hash": scan_hash}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        print("🛑 동적 분석 종료 완료")
    else:
        raise RuntimeError(f"❌ 동적 분석 종료 실패: {response.text}")

def run_dynamic_analysis_pipeline():
    config = load_config()
    apk_path = Path(config['FILE']['apk_path'])
    host = config['mobsf']['host']
    api_key = config['mobsf']['api_key']
    frida_script = config['Frida']['script']
    wait_time = int(config['dynamic']['wait_time'])
    package_name = config['dynamic']['package_name']
    app_name = config['dynamic']['app_name']
    report_output = Path(config['dynamic']['js_report_output'])

    print("[1] 앱 실행")
    launch_app(package_name)

    print("[2] Frida 스크립트 모니터링 시작")
    inject_frida_script(app_name, frida_script)

    print("[3] MobSF APK 업로드")
    scan_hash = upload_apk(apk_path, host, api_key)

    # 이후 동적 분석 시작
    print("[4] 동적 분석 시작")
    start_dynamic_analysis(scan_hash, host, api_key)

    print(f"[5] {wait_time}초 대기 후 리포트 수신")
    time.sleep(wait_time)

    print("[6] 보고서 저장")
    report = get_dynamic_report(scan_hash, host, api_key, report_output)
    report_output.parent.mkdir(parents=True, exist_ok=True)
    with open(report_output, "w", encoding="utf-8") as f:
        f.write("const dynamicReport = ")
        json.dump(report, f, indent=2)
        f.write(";")

    print("[7] 동적 분석 종료")
    stop_dynamic_analysis(scan_hash, host, api_key)
    print("🎉 동적 분석 파이프라인 완료!")
