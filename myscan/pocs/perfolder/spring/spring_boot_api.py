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
        self.name = "springboot-actuators-env"
        self.vulmsg = "Spring Boot 监控接口未关闭 "
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.url.count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        list = [
                "/env",
                "/actuator/env",
                "/appenv",
                "/actuator/appenv"
                    ]
        for i in list:
            req = {
                "method": "GET",
                "url": self.url + i,
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169"
                },
                "allow_redirects": False,
                "timeout": 10,
                "verify": False,
            }
            r = request(**req)
            if r != None and r.status_code == 200 and "java.vm.version" in r.text:
                parser_ = response_parser(r)
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
