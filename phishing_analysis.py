import config
import email
from emailrep import EmailRep
import file_sandbox
from PIL import Image
import reputation_check
import tkinter
from tkinter import filedialog
import webbrowser
import requests

def menu():
    print("\n")
    print("----------------------------------------")
    print("이메일 보안 (피싱 이메일 분석)")
    print("----------------------------------------")

    print("\n아래 옵션 중에서 선택해 주세요 : ")
    print("옵션 1: 이메일 주소 확인")
    print("옵션 2: 피싱 사이트 분석")
    print("옵션 3: 이메일 첨부파일 샌드박스")
    print("옵션 4: 이메일 헤더 분석")
    print("옵션 5: 피싱 공격 식별을 위한 일반 가이드라인")
    print("옵션 0: 종료")
    phishing_analysis_menu(int(input()))

def phishing_analysis_menu(selected_option):

    options = {
        1: email_address_validation,
        2: phishing_site,
        3: attachment_sandbox,
        4: header_analysis,
        5: guidelines,
        0: lambda: None
    }

    if selected_option in options:
        options[selected_option]()
    else:
        print("잘못된 입력입니다.")
        menu()

def email_address_validation():
    email_address = input("확인할 이메일 주소를 입력하세요: ").strip()
    print("\n")
    print("-----------------------")
    print("이메일 신뢰도 보고서")
    print("-----------------------")

    api_key = config.key_dictionary['ZeroBounce API Key']
    url = f"https://api.zerobounce.net/v2/validate?api_key={api_key}&email={email_address}"

    try:
        response = requests.get(url).json()

        # 주요 결과 필드 추출
        status = response.get('status', '정보 없음')
        sub_status = response.get('sub_status', '정보 없음')
        address = response.get('address', '정보 없음')
        account = response.get('account', '정보 없음')
        domain = response.get('domain', '정보 없음')
        did_you_mean = response.get('did_you_mean', '정보 없음')
        free_email = response.get('free_email', '정보 없음')
        mx_found = response.get('mx_found', '정보 없음')
        smtp_check = response.get('smtp_check', '정보 없음')
        catch_all = response.get('catch_all', '정보 없음')
        disposable = response.get('disposable', '정보 없음')
        toxic = response.get('toxic', '정보 없음')
        firstname = response.get('first_name', '정보 없음')
        lastname = response.get('last_name', '정보 없음')
        gender = response.get('gender', '정보 없음')
        country = response.get('country', '정보 없음')

        # 결과 출력 (f-string, 한국어)
        print(f"이메일 주소                  : {address}")
        print(f"검증 상태                    : {status}")
        print(f"상세 상태                    : {sub_status}")
        print(f"계정명                       : {account}")
        print(f"도메인                       : {domain}")
        print(f"오타 추천                    : {did_you_mean}")
        print(f"무료 이메일 여부             : {free_email}")
        print(f"MX 레코드 존재 여부          : {mx_found}")
        print(f"SMTP 검사 결과               : {smtp_check}")
        print(f"Catch-All 여부               : {catch_all}")
        print(f"일회용 메일 여부             : {disposable}")
        print(f"유해(스팸성) 이메일 여부      : {toxic}")
        print(f"이름                         : {firstname} {lastname}")
        print(f"성별                         : {gender}")
        print(f"국가                         : {country}")

    except Exception as e:
        print("이메일 정보를 확인할 수 없습니다.")

    menu()

def phishing_site():
    url = str(input("피싱 의심 사이트 주소를 입력해주세요: ").strip())
    reputation_check.check_url_reputation(url)
    menu()

def attachment_sandbox():
    file_sandbox.file_sandbox()
    menu()

def header_analysis():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(title="Select Message File(.eml)")
    f = open(root.filename)
    msg = email.message_from_file(f)
    f.close()
    parser = email.parser.HeaderParser()
    headers = parser.parsestr(msg.as_string())
    for h in headers.items():
        print(h)
    root.destroy()
    menu()

def guidelines():
    webbrowser.open(r'Phishing_Identification.png')
    menu()
