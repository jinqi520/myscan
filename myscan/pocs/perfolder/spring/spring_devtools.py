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
from myscan.config import scan_set


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "springboot-devtools"
        self.vulmsg = "spring devtools 反序列化漏洞"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
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
        req2 = {
            "method": "POST",
            "url": self.url + "/.~~spring-boot!~/restart",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
                "Content-Type": "application/octet-stream",
                "AUTH-TOKEN": "mysecret"
            },
            'data': "a",
            "allow_redirects": False,
            "timeout": 10,
            "verify": False,
        }
        r1 = request(**req1)
        r2 = request(**req2)
        if r1 != None and r2!= None and r1.status_code == 403 and r2.status_code == 500:
            parser_ = response_parser(r2)
            self.result.append({
                "name": self.name,
                "url": parser_.geturl(),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })
