✅ README.md


# 🔍 MobSF AutoAnalyzer

자동화된 MobSF 기반 APK 정적/동적 분석 도구입니다.  
복호화된 DEX 파일이 포함된 APK를 자동 리패키징하고,  
MobSF 서버를 실행해 정적/동적 분석 리포트를 자동으로 수집합니다.  


## 📁 프로젝트 구조

── apk_handler.py          # APK 복사, 리패키징, 서명 처리  
── bypass_security.js      # 동적 분석 중 후킹할 보안 우회 스크립트 (Frida)  
── config.ini              # 사용자 설정값 (MobSF 서버 경로 등)  
── config_loader.py        # 설정값 로딩 모듈  
── decryptor.py            # AES 키로 DEX 복호화 수행  
── dynamic_pipeline.py     # MobSF 동적 분석 자동화  
── mobsf_controller.py     # MobSF REST API 인터페이스  
── static_pipeline.py      # MobSF 정적 분석 자동화  
── main.py                 # 전체 파이프라인 실행 (Entry Point)  


## 🚀 사용 방법

### 1. 의존 패키지 설치

pip install -r requirements.txt  
⚠ pdfkit 사용을 위해 wkhtmltopdf를 사전에 설치해야 합니다.  

### 2. 실행

python main.py  

main.py는 다음 작업을 자동으로 수행합니다:  
복호화된 DEX 포함 APK 리패키징  
APK 서명  
MobSF 서버 자동 실행  
정적 & 동적 분석 자동 요청  
리포트 다운로드 및 저장  


### 3. 주의 사항
MobSF는 설치되어 있어야 하며, MobSF 작동에 필요한 설치가 먼저 완료 되어 있어야 합니다.  
분석할 APK는 APK_DIR에 위치해야 합니다.  

MobSF 동적 분석을 위해 디바이스 또는 에뮬레이터 연결이 필요합니다.  

- 작동 시, MobSF 서버와 Frida 가 실행 중이어야 합니다.  

[서명 파일 제작 예시]  
ex.  
(MAC 기준) keytool -genkeypair -v \  
-keystore mobsf-release-key.jks \  
-keyalg RSA \  
-keysize 2048 \  
-validity 10000 \  
-alias mobsf-key-alias \  
-dname "CN=sun, OU=security, O=groom, L=seoul, ST=seoul, C=KR" \  
-storepass 12345678 \  
-keypass 12345678  

[동적 분석 세팅 및 Frida 실행]  
ex.  
adb devices        # 디바이스 연결 확인  
adb root           # 루트 권한 활성화  
adb remount        # 시스템 파티션 remount (쓰기 가능 상태로)  
adb shell "/data/local/tmp/frida-server &"  #Frida 서버 백그라운드 실행  


### 4. 개발 환경  
Python 3.12.8  
MobSF 최신 버전 (로컬 실행)  
...  
