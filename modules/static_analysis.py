import os
import requests

def run_static_analysis(config, apk_path):
    server = config['server_ip']
    api_key = config['api_key']
    headers = {'Authorization': api_key}
    file_name = os.path.basename(apk_path)
    output_dir = os.path.join(os.path.dirname(apk_path), 'output')
    os.makedirs(output_dir, exist_ok=True)

    print(f"[+] APK 업로드 중: {file_name}")
    with open(apk_path, 'rb') as f:
        res = requests.post(f"{server}/api/v1/upload", headers=headers, files={'file': (file_name, f)})
    if res.status_code != 200:
        raise Exception(f"업로드 실패: {res.text}")
    resp_json = res.json()
    scan_hash = resp_json.get('hash')
    print(f"[+] 업로드 완료! 해시: {scan_hash}")

    print("[+] 정적 분석 시작...")
    res = requests.post(f"{server}/api/v1/scan", headers=headers, json={"hash": scan_hash})
    if res.status_code != 200:
        raise Exception(f"스캔 실패: {res.text}")
    print("[+] 정적 분석 완료!")

    print("[+] JSON 리포트 다운로드 중...")
    res = requests.post(f"{server}/api/v1/report_json", headers=headers, json={"hash": scan_hash})
    if res.status_code == 200:
        report_path = os.path.join(output_dir, file_name.replace(".apk", "_static.json"))
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(res.text)
        print(f"[+] JSON 보고서 저장 완료: {report_path}")
    else:
        print(f"[!] JSON 보고서 실패: {res.text}")

    print("[+] PDF 리포트 다운로드 중...")
    res = requests.post(f"{server}/api/v1/download_pdf", headers=headers, json={"hash": scan_hash})
    if res.status_code == 200:
        pdf_path = os.path.join(output_dir, file_name.replace(".apk", "_static.pdf"))
        with open(pdf_path, 'wb') as f:
            f.write(res.content)
        print(f"[+] PDF 보고서 저장 완료: {pdf_path}")
    else:
        print(f"[!] PDF 보고서 실패: {res.text}")
