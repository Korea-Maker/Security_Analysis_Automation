import brand_monit
import config
import dns_option
import file_sandbox
import phishing_analysis
import reputation_check
import sanitize
import time
import url_decoding


def main_switch(selected_option):
    if selected_option == 0:
        exit()

    options_map = {
        1: reputation_check.input_validate,
        2: dns_option.menu,
        3: phishing_analysis.menu,
        4: url_decoding.menu,
        5: file_sandbox.file_sandbox,
        6: sanitize.menu,
        7: brand_monit.menu,
        8: config.menu,
    }

    func = options_map.get(selected_option)
    try:
        if func:
            func()
    except:
        print("잘못된 입력입니다.")

if __name__ == '__main__' :
    print("\n")
    print("----------------------------------------")
    print("Security Analysis Automation")
    print("----------------------------------------")
    print("\nThe SOC Analyst's tool to automate"
    "\nthe investigation and validation of possible "
    "\nIndicators of Compromise (IOCs)")
    time.sleep(1)
    while True:
        try:
            config.fetch_api_key()
        except:
            print("\n\n안녕하세요, 사용자님!")
            print("\n이 스크립트를 처음 실행했거나, 암호화 키에 접근할 권한이 없거나, 키 파일이 삭제된 것 같습니다.")
            print("\n도움말 & 설정/재설정 메뉴로 이동합니다. 이미 키를 설정하셨다면, 충분한 권한으로 도구를 다시 실행해 주세요.")
            config.menu()
            config.fetch_api_key()

        print("\n아래 옵션 중 하나를 선택하세요 : ")
        print("옵션 1: 평판/블랙리스트 체크 (IP, 도메인, URL, 해시)")
        print("옵션 2: DNS/WHOIS 조회")
        print("옵션 3: 이메일 보안 (피싱 이메일 분석)")
        print("옵션 4: URL 디코딩 조사")
        print("옵션 5: 샌드박싱을 위한 파일 업로드")
        print("옵션 6: 이메일 IOCs(지표) 정규화")
        print("옵션 7: 브랜드 모니터링 및 분석")
        print("옵션 8: 도움말 & 설정/재설정")
        print("옵션 0: 도구 종료")
        
        selected_option=int(input())
        main_switch(selected_option)
