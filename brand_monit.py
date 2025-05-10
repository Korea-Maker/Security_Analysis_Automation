import config
import dns_option
import reputation_check
import requests
import time

def menu():
    print("\n")
    print("---------------------------")
    print("브랜드 모니터링 및 분석")
    print("---------------------------")

    print("\n아래에서 옵션을 선택하세요 : ")
    print("옵션 1: URL의 지리적 위치 확인")
    print("옵션 2: URL/소셜 미디어 계정/모바일 앱의 주요 UI 확인")
    print("옵션 3: URL 평판 확인")
    print("옵션 0: 종료")
    brand_monit_menu(int(input()))

def brand_monit_menu(selected_option):
    options = {
        1: url_geolocation,
        2: screenshot,
        3: url_reputation_check,
        0: lambda: None
    }

    if selected_option in options:
        options[selected_option]()
    else:
        print("잘못된 입력입니다.")
        menu()

def url_geolocation():
    dns_option.dnslookup()
    menu()

def screenshot():
    url = str(input("확인할 URL을 입력하세요 :")).strip()
    print("\n")
    print("------------------")
    print("URL SCAN IO 보고서")
    print("------------------")

    urlscanapikey = config.key_dictionary['URLScan IO API Key']
    scan_type = 'private'
    type = str(input('''공개 스캔을 실행하시겠습니까?[y/N]  
    공개 스캔 결과는 URL SCAN IO DB에 저장되며 인터넷에서 검색 가능합니다.  
    기본값은 비공개입니다.'''))

    if type == 'y':
        scan_type = 'public'
    
    headers = {'Content-Type': 'application/json','API-Key': urlscanapikey}
    try:
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            data='{"url": "%s", "%s": "on"}' % (url, scan_type)
        ).json()
        print(response['message'])
        print("공개/비공개 여부 :", response['visibility'])
        print("고유 ID          :", response['uuid'])

        if 'successful' in response['message']:
            print(f"{url}을(를) 스캔 중입니다.")
            print("\n")
            print("웹사이트가 로딩 완료될 때까지 기다리는 중입니다. 몇 분 정도 소요될 수 있습니다.")
            print("결과 페이지로 자동 이동하니, 명령을 다시 실행하지 않으셔도 됩니다!")

            time.sleep(50)
            final_response = requests.get(
                f'https://urlscan.io/api/v1/result/{response["uuid"]}/'
            ).json()

            print("\n")
            print("-----------------------")
            print("URL SCAN IO 상세 보고서")
            print("-----------------------")
            print("\n")
            print(f"스캔한 URL         : {final_response['task']['url']}")
            print(f"종합 점수          : {final_response['verdicts']['overall']['score']}")
            print(f"악성 여부          : {final_response['verdicts']['overall']['malicious']}")
            print(f"URL 스크린샷       : {final_response['task']['screenshotURL']}")
            print(f"URLSCAN 점수       : {final_response['verdicts']['urlscan']['score']}")
            if final_response['verdicts']['urlscan']['categories']:
                print("카테고리: ")
                for line in final_response['verdicts']['urlscan']['categories']:
                    print(f"\t{line}")
            print(f"URLSCAN 보고서 링크: {final_response['task']['reportURL']}")
    except:
        print("오류가 발생했습니다. 정책 또는 제한으로 인해 URL SCAN에서 도메인을 조회·스캔할 수 없습니다.")
    menu()

def url_reputation_check():
    url = str(input("URL을 입력하여 평판을 확인할 수 있습니다 :")).strip()
    reputation_check.check_url_reputation(url)
    menu()
