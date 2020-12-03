import requests

dnslog_phpsessionid = 'jinqi123123'
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:79.0) Gecko/20100101 Firefox/79.0",
    "Referer": "http://www.dnslog.cn/"
    }
subdomain = "jinqi9966"


def getdomain():
    url = "http://www.dnslog.cn/getdomain.php"
    x = requests.session()
    x.cookies['PHPSESSID'] = "jinqi123123"
    resp = x.get(url, headers=headers, verify=False)
    return subdomain + "." + resp.text


def getrecords():
    url = "http://www.dnslog.cn/getrecords.php"
    x = requests.session()
    x.cookies['PHPSESSID'] = "jinqi123123"
    resp = x.get(url, headers=headers, verify=False)
    if subdomain in resp.text:
        return True
    return False


if __name__ == "__main__":
    domain = getdomain()
    print(domain)
    try:
        # 每次getrecords()之前都会调用一次getdomain()，而getdomain()会清空记录，所以不存在因为上次的dns记录导致误报的清空
        print(1)
        #requests.get("http://" + domain)
    except:
        pass
    if getrecords():
        print("success")
    else:
        print("fail")
