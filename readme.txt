req1 = {
            "method": "POST",
            "url": self.url + "/.~~spring-boot!~/restart",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
                "Content-Type": "application/octet-stream",
                "AUTH-TOKEN": "jinqi123"
            },
            'data': "a",
            "allow_redirects": False,
            "timeout": 10,
            "verify": False,
        }
r1 = request(**req1)
if r1 != None and r1.status_code == 403: (判断是否为空，否则可能会报错)