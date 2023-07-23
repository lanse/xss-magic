#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 10:18 PM
# @Author  : w8ay
# @File    : loader.py
from urllib.parse import urlparse

import requests

from lib.controller.controller import task_push
from lib.core.common import isListLike, get_parent_paths
from lib.core.data import conf, KB, logger
from lib.core.enums import WEB_PLATFORM, OS, HTTPMETHOD
from lib.core.plugins import PluginBase
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp


class W13SCAN(PluginBase):
    type = 'loader'
    desc = '''Loader插件对请求以及响应进行解析，从而调度更多插件运行'''
    name = 'plugin loader'

    def audit(self):
        headers = self.requests.headers
        url = self.requests.url
        #logger.info("第一步在loader.py的27行")
        p = urlparse(url)
        if not p.netloc:
            return
        for rule in conf.excludes:#是否有禁止的网站地址
            if rule in p.netloc:
                logger.info("Skip domain:{}".format(url))
                return

        # fingerprint basic info
        exi = self.requests.suffix.lower()#判断网站什么格式
        if exi == ".asp":
            self.response.programing.append(WEB_PLATFORM.ASP)
            self.response.os.append(OS.WINDOWS)
        elif exi == ".aspx":
            self.response.programing.append(WEB_PLATFORM.ASPX)
            self.response.os.append(OS.WINDOWS)
        elif exi == ".php":
            self.response.programing.append(WEB_PLATFORM.PHP)
        elif exi == ".jsp" or exi == ".do" or exi == ".action":
            self.response.programing.append(WEB_PLATFORM.JAVA)
      #调用网站指纹，fingerprint目录下的每个插件
        for name, values in KB["fingerprint"].items(): #fingerprint里面的
            #logger.info(KB["fingerprint"])
            if not getattr(self.response, name):
                _result = []
                for mod in values:
                    m = mod.fingerprint(self.response.headers, self.response.text)#finggerprint插件里的方法，把结果放到_result列表里
                    if isinstance(m, str):
                        _result.append(m)
                    if isListLike(m):
                        _result += list(m)
                if _result:
                    setattr(self.response, name, _result)
        #logger.info("第二步在loader.py的62行")
        # Fingerprint basic end
        #调用针对文件的插件，对应插件目录PerFile
        if KB["spiderset"].add(url, 'PerFile'):#去重复爬虫
            task_push('PerFile', self.requests, self.response)

        # Send PerServer #调用针对主域名的插件,对应插件目录PerServer
        p = urlparse(url)
        domain = "{}://{}".format(p.scheme, p.netloc)
        if KB["spiderset"].add(domain, 'PerServer'):
            req = requests.get(domain, headers=headers, allow_redirects=False)
            fake_req = FakeReq(domain, headers, HTTPMETHOD.GET, "")
            fake_resp = FakeResp(req.status_code, req.content, req.headers)
            task_push('PerServer', fake_req, fake_resp) #调用一个插件

        # Collect directory from response
        #调用PerFolder下的插件分析各个目录
        urls = set(get_parent_paths(url))
        for parent_url in urls:
            if not KB["spiderset"].add(parent_url, 'get_link_directory'):
                continue
            req = requests.get(parent_url, headers=headers, allow_redirects=False)
            if KB["spiderset"].add(req.url, 'PerFolder'):
                fake_req = FakeReq(req.url, headers, HTTPMETHOD.GET, "")
                fake_resp = FakeResp(req.status_code, req.content, req.headers)
                task_push('PerFolder', fake_req, fake_resp)
