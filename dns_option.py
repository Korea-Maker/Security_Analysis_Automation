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

        ip = data_result.get("ip", "정보 없음")
        hostname = data_result.get("hostname", "정보 없음")
        org = data_result.get("org", "정보 없음")
        country = data_result.get("country", "정보 없음")
        region = data_result.get("region", "정보 없음")

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

    print("\n------------")
    print("WHOIS RECORD")
    print("------------")

    # 기본 정보 조회 - ipinfo.io 활용
    try:

        # ipinfo.io API로 기본 정보 조회
        api_token = config.key_dictionary['ipinfo API Key']
        url = f"https://ipinfo.io/{ip}/json"
        if api_token:
            url += f"?token={api_token}"

        response = requests.get(url)
        if response.status_code == 200:
            info = response.json()

            print(f"IP           : {info.get('ip', '정보 없음')}")
            print(f"호스트명     : {info.get('hostname', '정보 없음')}")
            print(f"도시         : {info.get('city', '정보 없음')}")
            print(f"지역         : {info.get('region', '정보 없음')}")
            print(f"국가         : {info.get('country', '정보 없음')}")
            print(f"위치         : {info.get('loc', '정보 없음')}")
            print(f"ORG          : {info.get('org', '정보 없음')}")

            # ASN 정보 출력
            if 'asn' in info:
                asn_info = info['asn']
                if isinstance(asn_info, dict):
                    print(f"ASN          : {asn_info.get('asn', '정보 없음')}")
                    print(f"ASN 이름     : {asn_info.get('name', '정보 없음')}")
                    print(f"ASN 도메인   : {asn_info.get('domain', '정보 없음')}")
                    print(f"ASN 종류     : {asn_info.get('type', '정보 없음')}")
                else:
                    print(f"ASN          : {asn_info}")
        else:
            print(f"ipinfo.io API 요청 실패: 상태 코드 {response.status_code}")

        try:
            import whois
            from ipaddress import ip_address, IPv4Address

            # IP 주소가 공인 IP인지 확인
            ip_obj = ip_address(ip)
            if not ip_obj.is_private:
                print("\n--- 추가 정보 ---")
                # IP 주소를 역방향 DNS로 도메인 찾기 시도
                try:
                    domain = socket.gethostbyaddr(ip)[0]
                    w = whois.whois(domain)

                    print(f"도메인       : {domain}")
                    print(f"등록자       : {w.registrar or '정보 없음'}")
                    print(f"생성일       : {w.creation_date or '정보 없음'}")
                    print(f"만료일       : {w.expiration_date or '정보 없음'}")
                    print(f"수정일       : {w.updated_date or '정보 없음'}")
                    print(f"이름서버     : {', '.join(w.name_servers) if w.name_servers else '정보 없음'}")
                except:
                    print("IP 주소에 대한 도메인 정보를 찾을 수 없습니다.")
        except ImportError:
            print("\npython-whois 라이브러리가 필요합니다: pip install python-whois")
        except Exception as whois_err:
            print(f"\nWHOIS 추가 정보 조회 중 오류: {whois_err}")

    except ImportError:
        print("requests 라이브러리가 필요합니다: pip install requests")
    except Exception as e:
        print(f"정보 조회 중 오류 발생: {e}")

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
