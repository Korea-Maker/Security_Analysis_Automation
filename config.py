from cryptography.fernet import Fernet
import ctypes
import os
import sys
import webbrowser

key_dictionary = dict()

def menu():
    print("\n")
    print("-----------------")
    print("도움말 및 설정 메뉴")
    print("-----------------")

    print("\n옵션을 선택하세요")
    print("옵션 1: 도움말")
    print("옵션 2: API Key 설정 또는 재설정")
    print("옵션 0: 종료")
    help_menu(int(input()))

def help_menu(selected_option):
    if selected_option == 1 :
        help_module()
    elif selected_option == 2 :
        api_key_config()
    elif selected_option == 0 :
        return
    else :
        print("잘못된 입력입니다.")
        menu()

def help_module():
    webbrowser.open('https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool/blob/main/README.md')
    menu()

def api_key_config():
    key = Fernet.generate_key()
    f = Fernet(key)
    api_key_filename = 'apiKeyFileName.ini'
    crypto_key_filename = 'cryptoKey.key'
    file_handle = open(api_key_filename, 'w')
    intel_list = ['VirusTotal', 'Abuse IP DB', 'URLScan IO', 'AlienVault OTX', 'Spyse', 'Email Reputation IO']
    for i in range(0, len(intel_list)):
        print("Enter your API Key for " + intel_list[i] + " :")
        api_key = str(input())
        __encrypted_api_key = f.encrypt(api_key.encode()).decode()
        file_handle.write(f"{intel_list[i]} API Key:{__encrypted_api_key}\n")

    try :
        os_platform = sys.platform
        if (os_platform == 'linux'):
            crypto_key_filename = '.' + crypto_key_filename
        with open(crypto_key_filename, 'w') as file :
            file.write(key.decode())

            if (os_platform == 'win32'):
                ctypes.windll.kernel32.SetFileAttributesW(crypto_key_filename, 2)
            else:
                pass
        print("설정 완료")
    except PermissionError:
        os.remove(crypto_key_filename)
        print("권한 오류가 발생했습니다.")
        print("스크립트를 다시 실행하세요.")
        sys.exit()
    menu()

def fetch_api_key():
    api_key_filename = 'apiKeyFileName.ini'
    os_platform = sys.platform
    if (os_platform == 'win32'):
        crypto_key_filename = 'cryptoKey.key'
    else :
        crypto_key_filename = '.cryptoKey.key'
    crypto_key = ''

    with open(crypto_key_filename, 'r') as key:
        crypto_key = key.read().encode()
    
    f = Fernet(crypto_key)

    with open(api_key_filename, 'r') as key:
        keys = key.readlines()
        for mykey in keys:
            api_key = mykey.strip('\n').split(':')
            original_key = f.decrypt(api_key[1].encode()).decode()
            #print(original_key)
            key_dictionary[api_key[0]] = original_key

