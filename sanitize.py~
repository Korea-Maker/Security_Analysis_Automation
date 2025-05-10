import re
import tkinter
from tkinter import filedialog


def menu():
    print("\n")
    print("----------------------------")
    print("이메일용 IOC 변환(비식별화)")
    print("----------------------------\n")
    print("아래 옵션 중 하나를 선택하세요 :")
    print("옵션 1: 단일 입력")
    print("옵션 2: 여러 값이 포함된 파일 업로드(대량 업로드)")
    print("옵션 0: 종료")
    sanitize_menu(int(input()))


def sanitize_menu(selected_option):
    if selected_option == 1:
        ioc_sanitize()
    elif selected_option == 2:
        bulk_ioc_sanitize()
    elif selected_option == 0:
        return
    else:
        print("잘못된 입력입니다.")
        menu()


def bulk_ioc_sanitize():
    import tkinter
    from tkinter import filedialog
    import re

    root = tkinter.Tk()
    root.withdraw()  # 창이 안 뜨게
    root.filename = filedialog.askopenfilename(title="텍스트 파일(.txt)을 선택하세요")
    ioclist = list()
    with open(root.filename, encoding='utf-8') as file:
        ioclist = [line.rstrip() for line in file]

    f = open('results.txt', 'w', encoding='utf-8')
    for ioc in ioclist:
        final_ioc = re.sub(r"\.", "[.]", ioc)
        final_ioc = re.sub(r"http://", "hxxp://", final_ioc)
        final_ioc = re.sub(r"https://", "hxxps://", final_ioc)
        final_ioc = re.sub(r"\:", "[:]", final_ioc)
        f.write(final_ioc.strip() + "\n")
    f.close()
    root.destroy()
    print("\n변환된 결과가 'results.txt'로 저장되었습니다.")
    menu()


def ioc_sanitize():
    import re

    ioc = str(input("비식별화하고 싶은 IoC(IP/도메인/URL)를 입력하세요: "))

    final_ioc = re.sub(r"\.", "[.]", ioc)
    final_ioc = re.sub(r"http://", "hxxp://", final_ioc)
    final_ioc = re.sub(r"https://", "hxxps://", final_ioc)
    final_ioc = re.sub(r"\:", "[:]", final_ioc)

    print("\n비식별화 결과 :", final_ioc)
    menu()