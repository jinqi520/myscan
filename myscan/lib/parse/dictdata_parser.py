# !/usr/bin/env python3
# @Time    : 2020-02-14
# @Author  : caicai
# @File    : dictdata_parser.py
from myscan.lib.core.common import getredis,verify_param,getmd5
import copy, base64
from urllib import parse


class dictdata_parser():
    '''
    此类功能为处理dictdata，写一些常用方法.
    '''

    def __init__(self, dictdata):
        self.dictdata = dictdata
        self.red = getredis()
        # self.red = ""
        data = copy.deepcopy(dictdata)
        self.url = data.get("url")
        self.request = data.get("request")
        self.request_bodyoffset = int(self.dictdata.get("request").get("bodyoffset"))
        self.response_bodyoffset = int(self.dictdata.get("response").get("bodyoffset"))

        self.response = data.get("response")
        self.keys = {
            "perfile": "doned_perfile",
            "perfolder": "doned_perfolder",
            "perscheme": "doned_perscheme",
        }

    def getfilepath(self):

        return "{protocol}://{host}:{port}{path}".format(**self.url)

    def getrootpath(self):

        return "{protocol}://{host}:{port}".format(**self.url)

    def getperfile(self):
        '''
        return string
        '''
        return self.url.get("url").split("?")[0]

    # 获取一个url所有的目录
    # array[:3] 但是不包括最后的login
    def getperfolders(self):
        '''
        return list ，every folder will endwith /
        '''
        folders = []
        url = self.url.get("url").split("?")[0]
        # url="http://www.myscantest.com:8888/admin/login"
        if url.count("/") == 3:
            return ["/".join(url.split("/")[:3]) + "/"]
        elif url.count("/") > 3:
            for x in range(3, url.count("/") + 1):
                folders.append("/".join(url.split("/")[:x]) + "/")
            return folders
        else:
            return []

    # 判断请求是否已经跑过perfile了
    def is_perfile_doned(self):
        '''
        return bool
        '''
        # 取uri的部分进行hash，sismember判断是否已经在集合中了，如果不在加入集合并返回false
        hashstr = getmd5(self.getperfile())[10:20]
        if not self.red.sismember(self.keys.get("perfile"), hashstr):
            self.red.sadd(self.keys.get("perfile"), hashstr)
            return False
        return True

    def is_perfolder_doned(self):
        '''
        return list
        '''
        res = []
        folders = self.getperfolders()
        if not folders:
            return []
        for folder in folders:
            hashstr = getmd5(folder)[10:20]
            if not self.red.sismember(self.keys.get("perfolder"), hashstr):
                self.red.sadd(self.keys.get("perfolder"), hashstr)
                res.append(folder)
        return res

    def getallargs(self):
        tmp = []
        params_body = self.dictdata.get("request").get("params").get("params_body")
        params_url = self.dictdata.get("request").get("params").get("params_url")
        params_cookie = self.dictdata.get("request").get("params").get("params_cookie")
        if params_body:
            for param in params_body:
                tmp.append(param.get("name"))
        if params_url:
            for param in params_url:
                tmp.append(param.get("name"))
        if params_cookie:
            for param in params_cookie:
                tmp.append(param.get("name"))
        return sorted(list(set(tmp)))

    def is_perscheme_doned(self):
        '''
        return bool
        '''
        method = self.dictdata.get("request").get("method")
        urlpath = self.dictdata.get("url").get("path")
        host = self.dictdata.get("url").get("host")
        protocol = self.dictdata.get("url").get("protocol")
        port = self.dictdata.get("url").get("port")
        argsname = "".join(self.getallargs())
        hashstr = getmd5("{}{}{}{}{}{}".format(protocol, host, port, method, urlpath, argsname))
        if not self.red.sismember(self.keys.get("perscheme"), hashstr):
            self.red.sadd(self.keys.get("perscheme"), hashstr)
            return False
        return True

    def getrequestbody(self):
        '''
        return bytes
        '''
        return base64.b64decode(self.dictdata.get("request").get("raw"))[self.request_bodyoffset:]

    def getresponsebody(self):
        '''
        return bytes
        '''
        return base64.b64decode(self.dictdata.get("response").get("raw"))[self.response_bodyoffset:]

    def getrequestparams_urlorcookie(self, source="url"):
        '''
        source accept:url and cookie
        return dict
        '''
        if source == "url":
            params = self.request.get("params").get("params_url")
        else:
            params = self.request.get("params").get("params_cookie")
        if params:
            resdict = {}
            for param in params:
                resdict[parse.unquote(param.get("name"))] = parse.unquote(param.get("value"))
            return copy.deepcopy(resdict)
        else:
            return {}

    def setrequestbody_newvalue(self, param, method="w", text="", urlencode=True):
        '''
        param : accpept dict
        method : accept a w . a:append ,w:write
        text: accept bytes and str
        urlencode: bool
        setvalue: bool ,setkey or value
        return bytearray
        '''
        if isinstance(text, str):
            text = text.encode()
        body = self.getrequestbody()
        if not body:
            return body
        else:
            value=verify_param(param,text,method,body,self.request_bodyoffset).encode()
            st = param.get("valuestart") - self.request_bodyoffset
            et = param.get("valueend") - self.request_bodyoffset
            bodyarray = bytearray(body)
            bodyarray[st: et] = value
            return bodyarray
    def setrequestbody_newkey(self, param, method="w", text=""):
        '''
        param : accpept dict
        method : accept a w . a:append ,w:write
        text: accept bytes and str
        urlencode: bool
        setvalue: bool ,setkey or value
        return bytearray
        '''
        if isinstance(text, str):
            text = text.encode()
        body = self.getrequestbody()
        if not body:
            return body
        if param.get("namestart")==-1:
            return body
        else:
            st = param.get("namestart") - self.request_bodyoffset
            et = param.get("nameend") - self.request_bodyoffset
            bodyarray = bytearray(body)
            if method == "w":
                return bodyarray[:st]+text+bodyarray[et:]
            else:
                return bodyarray[:et]+text+bodyarray[et:]

    def setrequesturlorcookie_newvalue(self, param, method="w", text="", urlencode=True, source="url"):
        '''
        param : accpept dict
        method : accept a w . a:append ,w:write
        text: accept bytes and str
        urlencode: bool
        source :accept url and cookie
        return dict
        '''
        if isinstance(text, bytes):
            text = text.decode()
        if source == "url":
            params = self.getrequestparams_urlorcookie("url")
        else:
            params = self.getrequestparams_urlorcookie("cookie")

        if not params:
            return {}
        else:
            value=verify_param(param,text,method,self.getrequestbody(),self.request_bodyoffset)
            newparams_url = copy.deepcopy(params)
            newparams_url[param.get("name")] = value
            return newparams_url
    def getreqfromparam(self, param, method="w", text=""):
        '''
        param : accpept dict
        method : accept a w . a:append ,w:write
        text: accept  str
        source :accept url and cookie
        return req
        '''
        if param.get("type") == 0: #url参数
            params_or_data = self.getrequestparams_urlorcookie("url")
        elif param.get("type")==2: #cookie参数
            params_or_data = self.getrequestparams_urlorcookie("cookie")
        else:
            params_or_data =self.getrequestbody()
        value=verify_param(param,text,method,self.getrequestbody(),self.request_bodyoffset)
        if param.get("type")==2:
            newparams_url = copy.deepcopy(params_or_data)
            newparams_url[param.get("name")] = value
            return self.generaterequest({"cookies":newparams_url})
        if param.get("type")==0:
            newparams_url = copy.deepcopy(params_or_data)
            newparams_url[param.get("name")] = value
            return self.generaterequest({"params":newparams_url})
        else:
            st = param.get("valuestart") - self.request_bodyoffset
            et = param.get("valueend") - self.request_bodyoffset
            bodyarray = bytearray(params_or_data)
            bodyarray[st: et] = value.encode()
            return self.generaterequest({"data":bodyarray})


    def getrequestraw(self):
        '''
        return bytes
        '''
        return base64.b64decode(self.request.get("raw"))

    def getresponseraw(self):
        '''
        return bytes
        '''
        return base64.b64decode(self.response.get("raw"))

    def generaterequest(self, req_payload):
        '''
        req_payload :dict
        '''
        req = {
            "method": self.dictdata.get("request").get("method"),
            "url": self.getfilepath(),
            "params": self.getrequestparams_urlorcookie("url"),
            "headers": copy.deepcopy(self.dictdata.get("request").get("headers")),
            "data": self.getrequestbody(),
            "timeout": 10,
            "verify": False,
            "allow_redirects": False,
        }
        req.update(req_payload)
        return req

    def addpayloadtobody(self, body, append_data=b"", find_str=b""):
        '''
        '''
        if isinstance(find_str, str):
            find_str = bytes(find_str)
        if isinstance(append_data, str):
            append_data = bytes(append_data)

        body = bytearray(body)
        place = body.find(find_str)
        data_withpayload = None
        if place != -1:
            data_withpayload = body[:place + len(find_str)] + append_data + body[place + len(find_str):]
        return data_withpayload
    def getrawrequest(self):
        '''
        return dict
        '''
        return {
            "method":self.request.get("method"),
            "url":self.getfilepath(),
            "headers":self.request.get("headers"),
            "params":self.getrequestparams_urlorcookie("url"),
            "data":self.getrequestbody()
        }
