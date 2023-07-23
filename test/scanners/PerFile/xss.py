#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/15 3:52 PM
# @Author  : w8ay
# @File    : xss.py
import copy
import html
import random
import re
import string
from urllib.parse import unquote

import requests

from lib.core.common import random_str, generateResponse, url_dict2str
from lib.core.data import conf
from lib.core.enums import HTTPMETHOD, PLACE, VulType
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.settings import XSS_EVAL_ATTITUDES, TOP_RISK_GET_PARAMS
from lib.helper.htmlparser import SearchInputInResponse, random_upper, getParamsFromHtml
from lib.helper.jscontext import SearchInputInScript
from lib.core.data import logger

class W13SCAN(PluginBase):
    name = 'XSS语义化探测插件'

    def init(self):
        self.result = ResultObject(self)
        self.result.init_info(self.requests.url, "XSS脚本注入", VulType.XSS)#初始化脚本

    def audit(self):
        parse_params = set(getParamsFromHtml(self.response.text)) #得到返回网页的参数值
        resp = self.response.text
        params_data = {}
        self.init()
        iterdatas = []
        
        parse_params = (parse_params | TOP_RISK_GET_PARAMS) - set(self.requests.params.keys())#得到常用参数和返回参数的并集
        # logger.info(parse_params)
        for key in parse_params:
            params_data[key] = "ooo"+key+"ooo*" #给每个参数配一个随机字符串
        params_data.update(self.requests.params) #放入参数中
        url=self.requests.url.split("?")[0]
        logger.info(params_data)
        logger.info(self.requests.headers)
        
        resp = requests.get("http://www.baobaidu.com",params=params_data, headers=self.requests.headers).text
    
        with open( 'test.txt', 'w',encoding='utf-8' ) as f:
            f.write(resp)
        # resp = requests.get(url, params=params_data, headers=self.requests.headers).text
        # logger.info(resp)
        # with open(r'd:/test.txt','w',encoding="utf-8") as f:
        #     f.write(resp)   

        #1.准备poc
        #2.发送请求
        #3.判断返回结果是否包含poc代码
        #logger.info("test1111")
        # headers=self.requests.headers
        # url=self.requests.url.split("?")[0]
        # default_params = self.requests.params#得到请求的参数
        
        # parse_params = set(getParamsFromHtml(self.response.text)) #得到返回网页的参数值
        # logger.info()
        # logger.info()
        # if(len(default_params)!=0):
        #     for key,value in default_params.items():
        #         parse_params.add(key)#把地址自带的参数放入参数集合里
       
       
    #    # print(conf.url)
    #     #1.准备poc
    #     payloads=[
    #         "<script>alert()</script>",
    #         "svg/onload=alert()>"
    #     ]
        
    #     #生成测试链接
    #     payload_url=[]
    #     new_params=list(parse_params)
    #     for payload in payloads:
    #         for param in new_params:
    #            payload_url.append(url.split("?")[0]+"?"+param+"="+payload)
    #     #logger.info(payload_url)
        # params_data = {}
        # self.init()
        # iterdatas = []
        # if self.requests.method == HTTPMETHOD.GET:
        #     parse_params = (parse_params | TOP_RISK_GET_PARAMS) - set(self.requests.params.keys())#得到常用参数和返回参数的并集
        #    # print(parse_params)
          
        # elif self.requests.method == HTTPMETHOD.POST:
        #     pass

        

        # if len(self.result.detail) > 0:
        #     self.success(self.result)
