#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : myscan_crlf.py
# refer:https://github.com/w-digital-scanner/w13scan/blob/master/W13SCAN/plugins/PerFile/crlf.py

import copy
import re
from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.const import notAcceptedExt
import requests


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get(
            "data")  # self.url为需要测试的url，但不会包含url参数，如https://www.baidu.com/index.php#tip1 .不会携带url参数，如?keyword=1
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "opne redirect or crlf"
        self.vulmsg = "get请求根据uri进行跳转时可能导致开放型重定向漏洞或crlf"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        parse = dictdata_parser(self.dictdata)
        if self.dictdata.get("request").get("method") == "GET" and self.dictdata.get("response").get("status") == 302 and self.dictdata.get("response").get("headers").get("Location") in parse.getperfile():
            self.result.append({
                "name": self.name,
                "url": self.url,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "text": "尝试将uri部分换成https://www.evil.com等poc进行重定向",
                    "request": "",
                    "response": "",
                }
            })
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36"
            }
            response = requests.get(self.url + "%0d%0ajinqi:%20crlf_test", headers=headers, allow_redirects=False)
            if "jinqi" in list(response.headers.keys()):
                self.result.append({
                    "name": self.name,
                    "url": self.url + "%0d%0ajinqi:%20crlf_test",
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "text": "存在crlf漏洞",
                        "request": "",
                        "response": "",
                        }
                    })

