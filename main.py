import sys
import traceback
from analyzer.config_loader import load_config
from analyzer.static_pipeline import run_static_analysis_pipeline
from analyzer.dynamic_pipeline import run_dynamic_analysis_pipeline

def main():
    try:
        print("📦 MobSF 분석기 실행")
        config = load_config()

        while True:
            print("\n[모드 선택] 정적 분석(s), 동적 분석(d), 종료(q)를 선택하세요:")
            print("s. 정적 분석")
            print("d. 동적 분석")
            print("q. 종료")

            choice = input("👉 선택 (s/d/q): ").strip().lower()

            if choice == "s":
                run_static_analysis_pipeline()

            elif choice == "d":
                run_dynamic_analysis_pipeline()

            elif choice == "q":
                print("👋 프로그램을 종료합니다.")
                break

            else:
                print("❌ 잘못된 입력입니다. s, d, q 중에서 선택하세요.")

    except Exception as e:
        print("\n❌ 오류 발생!")
        print(f"🛠 오류 메시지: {str(e)}")
        print("🔍 상세 내용:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
