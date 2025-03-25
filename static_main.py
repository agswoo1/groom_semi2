# main.py

import sys
import traceback
from modules.config_loader import load_config
from modules.mobsf_status import is_mobsf_alive
from modules.apk_handler import copy_apk, delete_temp_apk
from modules.decryption import decrypt_apk
from modules.static_analysis import run_static_analysis
#from modules.dynamic_analysis import run_dynamic_analysis

def main():
    try:
        print("[1] 설정 로드 중...")
        config = load_config()

        print("[2] MobSF 서버 상태 확인 중...")
        if not is_mobsf_alive(config['api_key'], config['server_ip']):
            raise ConnectionError("MobSF 서버에 연결할 수 없습니다. 먼저 서버를 실행했는지 확인하세요.")

        print("[3] APK 파일 복사 중...")
        copied_apk_path = copy_apk(config['apk_path'])

        print("[4] 복호화 진행 중...")
        decrypted_apk_path = decrypt_apk(copied_apk_path)

        print("[5] 정적 분석 시작...")
        run_static_analysis(config, decrypted_apk_path)

        #print("[6] 동적 분석 시작...")
        #run_dynamic_analysis(config, decrypted_apk_path)

        #print("[7] 분석 완료! 임시 파일 정리 중...")
        #delete_temp_apk(copied_apk_path)

        print("[^0^/] 모든 작업이 성공적으로 완료되었습니다.")

    except Exception as e:
        print("\n[!] 오류 발생!")
        print(f"[!] 오류 메시지: {str(e)}")
        print("[!] 상세 내용:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
