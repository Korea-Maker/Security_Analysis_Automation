import base64
import re
import requests
import urllib.parse


def menu():
    print("\n")
    print("----------------------------")
    print("조사용 URL 디코딩 도구")
    print("----------------------------\n")
    print("아래 옵션 중 하나를 선택하세요:")
    print("1: URL 디코더")
    print("2: Base64 디코더")
    print("3: Office365 SafeLink 디코더")
    print("4: 단축 URL 원래 주소 확인")
    print("0: 종료")
    try:
        selected = int(input("번호 입력: "))
    except:
        print("잘못된 입력입니다. 다시 입력해주세요.")
        return menu()
    url_decoding_menu(selected)


def url_decoding_menu(selected_option):
    if selected_option == 1:
        url_decoder()
    elif selected_option == 2:
        base64_decoder()
    elif selected_option == 3:
        office365_decoder()
    elif selected_option == 4:
        unshorten_url()
    elif selected_option == 0:
        print("프로그램을 종료합니다.")
        return
    else:
        print("잘못된 입력입니다. 다시 시도해주세요.")
        menu()


def url_decoder():
    print("\n")
    url = input("디코딩할 URL을 입력하세요: ").strip()

    print("\n------------------")
    print("기본 URL 디코더")
    print("------------------")
    try:
        decoded_url = urllib.parse.unquote(url)
        print("디코딩 결과:", decoded_url)
    except Exception as e:
        print("유효하지 않은 URL입니다:", e)
    menu()


def base64_decoder():
    print("\n")
    url = input("디코딩할 Base64 문자열을 입력하세요: ").strip()

    print("\n------------------")
    print("Base64 디코더")
    print("------------------")

    try:
        # base64 입력 길이 불일치 시 자동 맞춤
        missing_padding = len(url) % 4
        if missing_padding != 0:
            url += "=" * (4 - missing_padding)
        b64_decoded = base64.b64decode(url)
        try:
            decoded_url = b64_decoded.decode('utf-8')
        except UnicodeDecodeError:
            decoded_url = str(b64_decoded)
        print("디코딩 결과:", decoded_url)
    except Exception as e:
        print("유효하지 않은 Base64 문자열입니다:", e)
    menu()


def office365_decoder():
    print("\n")
    url = input("디코딩할 Office365 SafeLink URL을 입력하세요: ").strip()

    print("\n---------------------------")
    print("Office365 SafeLink 디코더")
    print("---------------------------")
    try:
        decoded_result = urllib.parse.unquote(url)
        # URL 내에서 "url=" 다음의 실제 URL 추출 로직 (구조에 따라 변형 가능)
        split_token = "url="
        start = decoded_result.find(split_token)
        if start == -1:
            raise ValueError("SafeLink 구조가 올바르지 않습니다.")
        final_url = decoded_result[start + len(split_token):]
        # 불필요한 파라미터 제거
        param_pos = final_url.find('&')
        if param_pos != -1:
            final_url = final_url[:param_pos]
        print("디코딩 결과:", final_url)
    except Exception as e:
        print("유효하지 않은 SafeLink입니다:", e)
    menu()


def unshorten_url():
    print("\n")
    url = input("원본 복원을 원하는 단축 URL을 입력하세요: ").strip()

    print("\n-------------------")
    print("단축 URL 복원 도구")
    print("-------------------")
    try:
        # 프로토콜이 없을 경우 추가
        if not url.lower().startswith(('http://', 'https://')):
            url = "http://" + url
        results = requests.get('https://unshorten.me/s/' + url)
        if results.status_code == 200:
            print("복원된 원본 URL:", results.text.strip())
        else:
            print("단축 URL 복원에 실패했습니다.")
    except Exception as e:
        print("유효하지 않은 URL입니다:", e)
    menu()
