import requests

def is_mobsf_alive(api_key, server_ip):
    try:
        url = f"{server_ip}/api/v1/scans"
        headers = {"Authorization": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print("[✓] MobSF 서버가 정상 작동 중입니다.")
            return True
        elif response.status_code == 401:
            print("[X] API 키가 유효하지 않습니다.")
        else:
            print(f"[X] 서버 응답 코드: {response.status_code}")
        return False
    except Exception as e:
        print(f"[!] 서버 확인 중 오류 발생: {e}")
        return False
