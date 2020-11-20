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
        self.name = "js sensitive"
        self.vulmsg = "js敏感信息泄露或者是跨站点脚本包含"
        self.level = 1  # 0:Low  1:Medium 2:High

    def verify(self):
        regx = [
            # 匹配url
            # r'(\b|\'|")(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do)(\b|\'|")',
            # 匹配邮箱, js中的邮箱古堡太多
            # r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
            # 匹配token或者密码泄露
            # 例如token = xxxxxxxx, 或者"apikey" : "xssss"
            r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
            # 匹配IP地址
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            # 匹配云泄露
            r'[\w]+\.cloudfront\.net',
            r'[\w\-.]+\.appspot\.com',
            r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*',
            r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
            r'(storage\.cloud\.google\.com\/[\w\-.]+)',
            r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
            # 匹配手机号
            r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}'
            # 匹配域名
            # r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',
        ]
        if self.dictdata.get("url").get("extension") == "js" and self.dictdata.get("response").get("status") == 200:
            for _ in regx:
                parser = dictdata_parser(self.dictdata)
                # re.I 是匹配大小写不敏感  re.M 多行匹配，影响^和$
                texts = re.findall(_, parser.getresponsebody().decode('GBK'), re.M | re.I)
                if texts:
                    for text in set(texts):
                        ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                        iscontinue = True

                        for i in ignores:
                            if i in text:
                                iscontinue = False
                                break
                        if not iscontinue:
                            continue
                        self.result.append({
                            "name": self.name,
                            "url": parser.getfilepath(),
                            "level": self.level,  # 0:Low  1:Medium 2:High
                            "detail": {
                                "vulmsg": self.vulmsg,
                                "text": "js文件中发现了如下敏感信息：" + text + ",如果是当前用户的信息请尝试跨站点脚本包含漏洞",
                                "request": parser.getrequestraw(),
                                "response": "",
                            }
                        })
