from pathlib import Path
from analyzer.config_loader import load_config
from analyzer.apk_handler import (
    copy_apk,
    delete_temp_apk,
    decompile_apk,
    rebuild_apk,
    sign_apk
)
from analyzer.decryptor import decrypt_apk
from analyzer.mobsf_controller import (
    is_mobsf_alive,
    upload_apk,
    run_static_analysis,
    download_pdf_report
)

def run_static_analysis_pipeline():
    print("[1] 설정 로드 중...")
    config = load_config()    
    mobsf_cfg = config['mobsf']
    apk_path = Path(config['FILE']['apk_path'])

    print("[2] MobSF 서버 상태 확인 중...")
    if not is_mobsf_alive(mobsf_cfg['host'], mobsf_cfg['api_key']):
        raise ConnectionError("MobSF 서버에 연결할 수 없습니다. 먼저 서버를 실행했는지 확인하세요.")

    print("[3] APK 복사 중...")
    copied_apk_path = copy_apk(str(apk_path))

    print("[4] APK 디컴파일 중...")
    decompiled_path = decompile_apk(copied_apk_path)

    print("[5] DEX 복호화 수행 중...")
    decrypt_apk(str(decompiled_path))

    print("[6] 리패키징 중...")
    rebuild_apk(decompiled_path, copied_apk_path)

    print("[7] 서명 중...")
    sign_apk(copied_apk_path, config['signing'])

    print("[8] MobSF에 업로드 및 정적 분석 중...")
    scan_hash = upload_apk(
        apk_path=copied_apk_path,
        host=mobsf_cfg['host'],
        api_key=mobsf_cfg['api_key']
    )

    run_static_analysis(
        scan_hash=scan_hash,
        host=mobsf_cfg['host'],
        api_key=mobsf_cfg['api_key']
    )

    print("[9] PDF 보고서 다운로드 중...")
    wkhtmltopdf_path = config['pdf']['wkhtmltopdf_path']
    download_pdf_report(
    scan_hash=scan_hash,
    host=mobsf_cfg['host'],
    api_key=mobsf_cfg['api_key'],
    output_path=Path("output/report.pdf"),
    wkhtmltopdf_path=wkhtmltopdf_path
    )

    print("[10] 복사된 분석용 APK 삭제 중...")
    delete_temp_apk(copied_apk_path)

    print("\n🎉 모든 작업이 성공적으로 완료되었습니다.")