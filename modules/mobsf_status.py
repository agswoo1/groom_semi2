import requests

def is_mobsf_alive(server_ip: str) -> bool:
    """MobSF 서버가 정상적으로 실행 중인지 확인합니다."""
    try:
        url = f"{server_ip}/api/v1/info"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            print("[+] MobSF 서버 응답 확인됨.")
            return True
        else:
            print(f"[!] MobSF 응답 상태 코드: {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[!] MobSF 서버 연결 실패: {e}")
        return False
