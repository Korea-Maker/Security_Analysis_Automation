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

    ip = str(input("Enter IP Address to check :").strip())
    
    try:
        client = Client(config.key_dictionary['Spyse API Key'])
        ip_details = client.get_ip_details(ip)
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        addr = str(res['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n")
        print("------------")
        print("WHOIS RECORD")
        print("------------")
        print("CIDR         :" + str(res['nets'][0]['cidr']))
        print("Name         :" + str(res['nets'][0]['name']))
        print("Range        :" + str(res['nets'][0]['range']))
        print("Descr        :" + str(res['nets'][0]['description']))
        print("Country      :" + str(res['nets'][0]['country']))
        print("Address      :" + addr)
        if str(ip_details.ports) != "None" :
            print("Domain Name   :", str(ip_details.ports[0].http_extract.final_redirect_url.host))
            print("Full URL      :", str(ip_details.ports[0].http_extract.final_redirect_url.full_uri))
        print("ISP Details  :", str(ip_details.isp_info))
        print("Created      :" + str(res['nets'][0]['created']))
        print("Updated      :" + str(res['nets'][0]['updated']))
        menu()
    except:
        print("Invalid or Private IP Address")
        menu()

def isplookup() :
    ip_address = str(input("Enter IP Address to check :").strip())
    print("\n")
    print("----------")
    print("ISP RECORD")
    print("----------")
    try:
        client = Client(config.key_dictionary['Spyse API Key'])
        ip_details = client.get_ip_details(ip_address)
        print("\nIP Address    :", ip_details.ip)
        print("AS Number       :", str(ip_details.isp_info.as_num))
        print("AS Organization :", str(ip_details.isp_info.as_org))
        print("ISP             :", str(ip_details.isp_info.isp))
        print("City Name       :", str(ip_details.geo_info.city_name))
        print("City Name       :", str(ip_details.geo_info.country))
        print("City Name       :", str(ip_details.geo_info.country_iso_code))
        print("Location        :", str(ip_details.geo_info.location))
        if str(ip_details.ports) != "None" :
            print("Domain Name   :", str(ip_details.ports[0].http_extract.final_redirect_url.host))
            print("Full URL      :", str(ip_details.ports[0].http_extract.final_redirect_url.full_uri))
        menu()
    except:
        print("Hostname for give IP not found")
        menu()
