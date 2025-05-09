import config
import socket
from ipwhois import IPWhois
from urllib.parse import urlparse
import requests
import dns.resolver


def menu():
    print("\n")
    print("-----------")
    print("DNS OPTIONS")
    print("-----------")

    print("\n아래에서 옵션을 선택해 주세요 : ")
    print("옵션 1: 역방향 DNS 조회")
    print("옵션 2: DNS 조회")
    print("옵션 3: WHOIS 조회")
    print("옵션 4: ISP 조회")
    print("옵션 0: 종료")
    dnsmenu(int(input()))


def dnsmenu(selected_option):
    options = {
        1: reversedns,
        2: dnslookup,
        3: whoislookup,
        4: isplookup,
        0: lambda: None
    }

    if selected_option in options:
        options[selected_option]()
    else:
        print("잘못된 입력입니다.")
        menu()

# def reversedns():
#     ip_address = str(input("Enter IP Address to check :").strip())
#
#     print("\n")
#     print("------------------")
#     print("REVERSE DNS RECORD")
#     print("------------------")
#
#     try: # Spyse 서비스 종료
#         client = Client(config.key_dictionary['Spyse API Key'])
#         ip_details = client.get_ip_details(ip_address)
#         print("\nIP Address  :", ip_details.ip)
#         if str(ip_details.ports) != "None" :
#             print("Domain Name   :", str(ip_details.ports[0].http_extract.final_redirect_url.host))
#             print("Full URL      :", str(ip_details.ports[0].http_extract.final_redirect_url.full_uri))
#         print("ISP Details   :", str(ip_details.isp_info))
#         menu()
#     except:
#         print("Hostname for give IP not found")
#         menu()

def reversedns():
    ip_address = input("확인할 IP 주소를 입력하세요: ").strip()

    print("\n------------------")
    print("REVERSE DNS RECORD")
    print("------------------\n")


    try:
        api_token = config.key_dictionary['ipinfo API Key']
        url = f"https://ipinfo.io/{ip_address}/json?token={api_token}"

        response = requests.get(url)

        data_result = response.json()
        ip = data_result["ip"]
        hostname = data_result["hostname"]
        org = data_result["org"]
        country = data_result["country"]
        region = data_result["region"]

        print(f"IP: {ip}")
        print(f"호스트명: {hostname}")
        print(f"ORG: {org}")
        print(f"국가: {country}")
        print(f"지역: {region}")

        menu()
    except Exception as e:
        print("IP 또는 호스트 정보를 찾을 수 없습니다.")
        print("오류:", e)
        menu()

def dnslookup():
    hostname = input("확인할 도메인 또는 URL을 입력하세요: ").strip()
    final_domain = urlparse(hostname).netloc if urlparse(hostname).netloc else hostname

    print("\n----------")
    print("DNS RECORD")
    print("----------\n")
    try:
        ip_address = socket.gethostbyname(final_domain)
        api_token = config.key_dictionary['ipinfo API Key']
        url = f"https://ipinfo.io/{ip_address}/json?token={api_token}"
        response = requests.get(url)
        ipinfo = response.json()

        print(f"\nIP Address      : {ip_address}")
        print(f"Organization    : {ipinfo.get('org', '정보 없음')}")
        print(f"Country         : {ipinfo.get('country', '정보 없음')}")
        print(f"ISP (as)        : {ipinfo.get('as', '정보 없음')}")
        print(f"지역            : {ipinfo.get('region', '정보 없음')}, {ipinfo.get('city', '')}")

        # DNS 레코드 예시 (A, MX, NS)
        print("DNS Records:")
        for record_type in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(final_domain, record_type)
                for rdata in answers:
                    print(f"{record_type} : {rdata}")
            except Exception:
                pass

        menu()
    except Exception as e:
        print("도메인에 대한 IP 주소를 찾을 수 없습니다.")
        print("오류:", e)
        menu()

def whoislookup():
    ip = input("확인할 IP 주소를 입력하세요: ").strip()
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        addr = str(res['network']['address']).replace('\n', ', ')
        print("\n------------")
        print("WHOIS RECORD")
        print("------------")
        print(f"CIDR         : {res['network']['cidr']}")
        print(f"Name         : {res['network']['name']}")
        print(f"Range        : {res['network']['start_address']} - {res['network']['end_address']}")
        print(f"Descr        : {res['network']['remarks']}")
        print(f"Country      : {res['network']['country']}")
        print(f"Address      : {addr}")
        print(f"Created      : {res['network']['created']}")
        print(f"Updated      : {res['network']['updated']}")

        # ISP 및 ORG 정보 (ipinfo.io 추가 출력)
        api_token = config.key_dictionary['ipinfo API Key']
        url = f"https://ipinfo.io/{ip}/json?token={api_token}"
        response = requests.get(url)
        info = response.json()
        print(f"ORG          : {info.get('org', '정보 없음')}")
        print(f"ASN          : {info.get('asn', {}).get('asn', '정보 없음')}")
        menu()
    except Exception as e:
        print("잘못됐거나 사설 IP 주소입니다.")
        print("오류:", e)
        menu()

def isplookup():
    ip_address = input("확인할 IP 주소를 입력하세요: ").strip()
    print("\n----------")
    print("ISP RECORD")
    print("----------")
    try:
        api_token = config.key_dictionary['ipinfo API Key']
        url = f"https://ipinfo.io/{ip_address}/json?token={api_token}"
        response = requests.get(url)
        info = response.json()

        print(f"\nIP Address      : {info.get('ip')}")
        print(f"ASN             : {info.get('asn', {}).get('asn', '-') if info.get('asn') else '정보 없음'}")
        print(f"AS Org          : {info.get('asn', {}).get('name', '-') if info.get('asn') else info.get('org', '정보 없음')}")
        print(f"ORG/ISP         : {info.get('org', '정보 없음')}")
        print(f"도시            : {info.get('city', '')}")
        print(f"지역            : {info.get('region', '')}")
        print(f"국가            : {info.get('country', '')}")
        print(f"좌표            : {info.get('loc', '')}")
        menu()
    except Exception as e:
        print("해당 IP에 대한 정보를 찾을 수 없습니다.")
        print("오류:", e)
        menu()
