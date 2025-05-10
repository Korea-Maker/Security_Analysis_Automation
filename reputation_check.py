import base64
import config
from ipwhois import IPWhois
import json
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import re
import requests
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

def input_validate():
    print("\n")
    print("-----------------")
    print("평판 조회")
    print("-----------------")

    userinput = input("IP, Domain, URL 또는 File Hash를 입력해주세요 : ").split()
    ipregex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    domainregex = r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$"
    hashregex = r"^[a-fA-F0-9]+$"
    #print(userinput)
    if (re.search(ipregex, userinput[0])):
        check_ip_reputation(userinput[0])
    if (re.search(r":\/\/", userinput[0])):
        check_url_reputation(userinput[0])
    if (re.search(domainregex, userinput[0])):
        check_url_reputation(userinput[0])
    if (re.search(hashregex, userinput[0])):
        check_hash_reputation(userinput[0])

def check_ip_reputation(ip):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = config.key_dictionary['VirusTotal API Key']
    try:
        response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip, headers={'x-apikey': '%s' % vtapikey})
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)
        reference = "https://www.virustotal.com/gui/ip-address/"+ip
        print("IP 주소                        :", ip)
        if 'as_owner' in resp['data']['attributes']:
            print("IP 소유자                      :", str(resp['data']['attributes']['as_owner']))
        print("시도된 스캔 수                 :", str(resp['data']['attributes']['last_analysis_stats']))
        print("신뢰도 점수                    :", str(resp['data']['attributes']['reputation']))
        print("\n악성/의심 신고 건수            :",
              int(resp['data']['attributes']['last_analysis_stats']['malicious']) + int(
                  resp['data']['attributes']['last_analysis_stats']['suspicious']))
        print("Virustotal 상세 보고서 링크     :", reference)
    except:
        print("IP를 찾을 수 없거나 잘못된 입력입니다.")

    print("\n")
    print("-----------------")
    print("ABUSEIPDB REPORT")
    print("-----------------")

    ABIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
    days = '180'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': days
    }
    headers = {
        'Accept': 'application/json',
        'Key': config.key_dictionary['Abuse IP DB API Key']
    }
    reference = "https://www.abuseipdb.com/check/"+ip

    try:
        response = requests.get(ABIPDB_URL, headers=headers, params=querystring, verify=False)
        result = response.json()
        data = result.get('data', {})
        print(f"\nIP 주소:            {data.get('ipAddress', '정보 없음')}")
        print(f"신고된 횟수:         {data.get('totalReports', '정보 없음')}")
        print(f"악용 신뢰도 점수:    {data.get('abuseConfidenceScore', '정보 없음')}%")
        print(f"마지막 신고 날짜:     {data.get('lastReportedAt', '없음')}")
        print(f"신고 상세보기:       {reference}")
    except Exception as e:
        print("IP 정보를 찾을 수 없습니다.")
        print("오류:", e)

    print("\n")
    print("---------------------")
    print("AlienVault OTX REPORT")
    print("---------------------")
    
    try:
        BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
        API_KEY = config.key_dictionary['AlienVault OTX API Key']
        url = 'indicators/IPv4/'
        #section = ''
        headers = {
            'accept': 'application/json',
            'X-OTX-API-KEY': API_KEY,
        }

        reference = "https://otx.alienvault.com/indicator/ip/" + ip
        response = requests.get(BASE_URL + url + ip + '/', headers=headers)
        resp = response.json()
        print("IP 주소          :", resp['indicator'])
        print("IP 주소 유형     :", resp['type'])
        print("소유자/ASN       :", resp['asn'])
        print("도시             :", resp['city'])
        print("국가             :", resp['country_name'])
        tags = dict()
        for i in range(0, resp['pulse_info']['count']):
            for l in resp['pulse_info']['pulses'][i]['tags']:
                tags[l] = tags.get(l, 0) + 1
        print("태그             :", tags)
        print("참고 링크        :", reference)
    except:
        print("AlienVault OTX 검색 결과 IP를 찾을 수 없습니다.")

    # print("\n")
    # print("------------")
    # print("SPYSE REPORT")
    # print("------------")
    #
    # client = Client(config.key_dictionary['Spyse API Key'])
    # reference = "https://spyse.com/search?query=%s&target=ip"%ip
    #
    # try:
    #     ip_details = client.get_ip_details(ip)
    #     print("\nIP Address           :", str(ip_details.ip))
    #     print("Severity out of 100    :", str(ip_details.abuses.score))
    #     print("Is the IP dangerous    :", str(ip_details.security_score.score))
    #     print("CVE List               :", str(ip_details.cve_list))
    #     print("Spyse Report Reference :", reference)
    # except:
    #     print("IP not found")

    try:
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        addr = str(res['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n")
        print("------------")
        print("WHOIS 정보")
        print("------------")
        print("CIDR 대역     :", str(res['nets'][0]['cidr']))
        print("네트워크 이름 :", str(res['nets'][0]['name']))
        print("IP 범위       :", str(res['nets'][0]['range']))
        print("설명          :", str(res['nets'][0]['description']))
        print("국가          :", str(res['nets'][0]['country']))
        print("주소          :", addr)
        print("등록일        :", str(res['nets'][0]['created']))
        print("수정일        :", str(res['nets'][0]['updated']))
    except:
        print("잘못된 IP 주소이거나 사설 IP 주소입니다.")

    print("\n\n")
    ret = int(input("메뉴로 돌아가려면 1을 입력하세요."))
    if ret == 1:
        return
    else:
        print("잘못된 입력입니다. 그래도 계속 진행합니다.")
        return

def check_url_reputation(url):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = config.key_dictionary['VirusTotal API Key']
    try:
        baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': vtapikey, 'resource': url }
        response = requests.get(baseurl, params=params)
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)
        
        #print(resp) # VIRUSTOTAL IS NOT A GREAT RESOURCE FOR URL REPUTATION however v2 works fine 
        print("제출한 URL                   :", str(resp['url']))
        print("분석 시도 횟수               :", str(resp['total']))
        print("악성으로 보고된 횟수         :", str(resp['positives']))
        print("Virustotal 상세 보고서 링크   :", str(resp['permalink']))

        res = list(resp['scans'].values())
        tags = dict()
        for i in range(0, len(res)):
            tags[str(res[i]['result'])] = tags.get(str(res[i]['result']), 0) + 1
        print("태그                        :", tags)
    except:
        print("URL을 찾을 수 없거나, 잘못 입력하였습니다.")

    print("\n")
    print("-----------------------")
    print("AlienVault OTXv2 REPORT")
    print("-----------------------")

    try:
        otx = OTXv2(config.key_dictionary['AlienVault OTX API Key'])
        final_domain = urlparse(url).netloc
        results = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, final_domain)
        print("도메인(URL)                  :", results['general']['indicator'])
        print("유형                         :", results['general']['type_title'])
        print("감지된 건수(펄스 개수)       :", results['general']['pulse_info']['count'])
        # print(results['geo']['asn'])
        # print(results['geo']['country_name'])
        print("악성코드(멀웨어) 감지 개수    :", len(results['malware']['data']))
        print("URL 리스트 개수               :", len(results['url_list']['url_list']))
        # print(results)
        tags = list()
        for i in range(0, len(results['general']['validation'])):
            tags.append(results['general']['validation'][i]['name'])
        length_of_validation = len(tuple(tags))
        if length_of_validation > 0:
            print("검증(Validation) 태그         :", tuple(tags))
        else:
            print("검증 태그                     : 주요 검색엔진에 등록되지 않아 의심스러운 도메인/URL입니다.")
    except:
        print("AlienVault OTX 검색에서 URL을 찾을 수 없습니다.")

    print("\n")
    print("----------------")
    print("Phishtank Report")
    print("----------------")

    try:
        headers = {
            'format': 'json'
        }

        BASE_URL = "http://checkurl.phishtank.com/checkurl/"
        new_check_bytes = url.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        BASE_URL += base64_new_check
        response = requests.request("POST", url=BASE_URL, headers=headers)
        # print(response.text)
        root = ET.fromstring(response.text)
        print("제출한 URL         :", root[1][0][0].text)
        print("DB에서 발견 여부    :", root[1][0][1].text)
        print("피싱 ID             :", root[1][0][2].text)
        print("참고 링크           :", root[1][0][3].text)
        print("검증 여부           :", root[1][0][4].text)
        if root[1][0][4].text == 'true':
            print("검증 날짜           :", root[1][0][5].text)
            print("여전히 유효 여부    :", root[1][0][6].text)
    except:
        print("해당 URL은 Phishtank 데이터베이스에 피싱으로 등록되어 있지 않습니다.")

    print("\n")
    print("------------------")
    print("URL SCAN IO REPORT")
    print("------------------")
    
    urlscanapikey = config.key_dictionary['URLScan IO API Key']
    scan_type = 'private'
    type = str(input('''공개 스캔을 실행하시겠습니까?[y/N]  
        공개 스캔 결과는 URL SCAN IO DB에 등록되어 인터넷에서 검색 가능합니다.  
        기본값은 비공개입니다.'''))

    if type == 'y':
        scan_type = 'public'
    
    headers = {'Content-Type': 'application/json','API-Key': urlscanapikey,}
    try:
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            data='{"url": "%s", "%s": "on"}' % (url, scan_type)
        ).json()
        print(response['message'])
        print("공개/비공개 여부 :", response['visibility'])
        print("고유 ID         :", response['uuid'])

        if 'successful' in response['message']:
            print("%s을(를) 스캔 중입니다." % url)
            print("\n")
            print("웹사이트가 로딩될 때까지 잠시 기다려주세요. 이 과정은 다소 시간이 걸릴 수 있습니다.\n결과 페이지로 자동 이동하니, 명령을 다시 실행할 필요는 없습니다!")
            time.sleep(50)
            final_response = requests.get('https://urlscan.io/api/v1/result/%s/' % response['uuid']).json()
            # print(final_response)
            print("\n")
            print("----------------------")
            print("URL SCAN IO 보고서")
            print("----------------------")
            print("\n")
            print("스캔한 URL              :", str(final_response['task']['url']))
            print("종합 점수               :", str(final_response['verdicts']['overall']['score']))
            print("악성 여부               :", str(final_response['verdicts']['overall']['malicious']))
            print("URL 스크린샷            :", str(final_response['task']['screenshotURL']))
            print("URLSCAN 점수            :", str(final_response['verdicts']['urlscan']['score']))
            if final_response['verdicts']['urlscan']['categories']:
                print("카테고리: ")
                for line in final_response['verdicts']['urlscan']['categories']:
                    print("\t" + str(line))
            print("URLSCAN 보고서 링크      :", str(final_response['task']['reportURL']))
    except:
        print("오류가 발생했습니다. URL SCAN에서 도메인을 확인하거나 스캔할 수 없습니다(제한이 있을 수 있습니다).")

    print("\n\n")
    ret = int(input("메뉴로 돌아가려면 1을 입력하세요."))
    if ret == 1:
        return
    else:
        print("잘못된 입력입니다. 그래도 계속 진행합니다.")
        return

def check_hash_reputation(hash):
    
    print("\n")
    print("-----------------------")
    print("AlienVault OTXv2 REPORT")
    print("-----------------------")
    reference = "https://otx.alienvault.com/indicator/file/" + hash
    try:
        BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
        API_KEY = config.key_dictionary['AlienVault OTX API Key']
        url = 'indicators/file/'
        section = 'analysis'
        headers = {
            'accept': 'application/json',
            'X-OTX-API-KEY': API_KEY,
        }

        reference = "https://otx.alienvault.com/indicator/file/" + hash
        response = requests.get(BASE_URL + url + hash + '/' + section, headers=headers)
        resp = response.json()
        # print(resp)
        print("해시                  :", hash)
        print("파일 유형             :", resp['analysis']['info']['results']['file_type'])
        print("Cuckoo 샌드박스 점수  :", resp['analysis']['plugins']['cuckoo']['result']['info']['combined_score'])
        print("서명 개수             :", len(resp['analysis']['plugins']['cuckoo']['result']['signatures']))
        print("MS-디펜더 결과        :", resp['analysis']['plugins']['msdefender']['results'])
        print("Avast 백신 결과       :", resp['analysis']['plugins']['avast']['results'])
        print("원본 파일명(Exif 도구):", resp['analysis']['plugins']['exiftool']['results']['EXE:OriginalFileName'])
        print("제품명                :", resp['analysis']['plugins']['exiftool']['results']['EXE:ProductName'])
        print("파일 플랫폼           :", resp['analysis']['plugins']['exiftool']['results']['EXE:FileOS'])
    except:
        print("완전한 세부 정보를 가져오지 못했습니다. 자세한 정보는 아래 링크를 브라우저로 방문해 확인하세요.")
        print("참조                  :", reference)

    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = config.key_dictionary['VirusTotal API Key']
    try:
        response = requests.get(
            "https://www.virustotal.com/api/v3/files/%s" % hash,
            headers={'x-apikey': '%s' % vtapikey}
        ).json()
        res_str = json.dumps(response)
        resp = json.loads(res_str)
        # print(resp)
        reference = "https://www.virustotal.com/gui/file/" + hash

        no_of_reporting = int(resp['data']['attributes']['last_analysis_stats']['malicious']) + int(
            resp['data']['attributes']['last_analysis_stats']['suspicious'])
        print("제출한 해시값           :", hash)
        print("파일 유형               :", str(resp['data']['attributes']['type_description']))
        print("전체 탐지 내역           :", str(resp['data']['attributes']['last_analysis_stats']))
        print("악성/의심 보고 횟수      :", no_of_reporting)
        if 'signature_info' in resp['data']['attributes']:
            print("파일 시그니처           :", str(resp['data']['attributes']['signature_info']))
        if 'popular_threat_classification' in resp['data']['attributes']:
            print("위협 분류 라벨           :",
                  str(resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))
        print("Virustotal 참고 링크     :", reference)
    except:
        print("완료되었습니다!")

    print("\n")
    ret = int(input("메뉴로 돌아가려면 1을 입력하세요: "))
    if ret == 1:
        return
    else:
        print("잘못된 입력입니다. 그래도 계속 진행합니다.")
        return
