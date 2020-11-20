# !/usr/bin/env python3
# @Time    : 2020/7/26
# @Author  : caicai
# @File    : weblogic_cve_2020_2555.py


from myscan.lib.hostscan.pocbase import PocBase
from myscan.lib.core.data import paths, cmd_line_options
from myscan.lib.hostscan.common import get_data_from_file, start_process
from myscan.lib.core.common import get_random_str
from myscan.lib.core.common_reverse import generate, query_reverse, generate_reverse_payloads
import os
import requests
from myscan.lib.helper.commons import generateResponse

'''
执行ping命令dnslog检测
'''


class POC(PocBase):
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详见 Class3-hostscan开发指南.md
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.addr = self.dictdata.get("addr")  # type:str
        self.port = self.dictdata.get("port")  # type:int
        # 以下根据实际情况填写
        self.name = "iis 解析漏洞"
        self.vulmsg = ""
        self.level = 2  # 0:Low  1:Medium 2:High
        self.require = {
            "service": ["http", "https"],
            "type": "tcp"
        }
        # 自定义参数

    def verify(self):
        if not self.check_rule(self.dictdata, self.require):  # 检查是否满足测试条件
            return
        domain = "{}://{}/".format(self.addr, self.port)
        payload = domain + "robots.txt/.php"
        headers = self.dictdata.request.headers
        r = requests.get(payload, headers=headers, allow_redirects=False)
        ContentType = r.headers.get("Content-Type", '')
        if 'html' in ContentType and "allow" in r.text:
            self.result.append({
                "name": self.name,
                "url": payload,
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "request": r.reqinfo,
                    "response": generateResponse(r)
                }
            })