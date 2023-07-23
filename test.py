import inspect
import os
import sys
import threading
from html.parser import HTMLParser
import requests
from colorama import deinit
import pyjsparser
from lib.controller.controller import start, task_push_from_name
from lib.core.enums import HTTPMETHOD
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
from lib.proxy.baseproxy import AsyncMitmProxy
from html import unescape
import re
from html.parser import HTMLParser
from lib.helper.jscontext import analyse_js
from lib.parse.cmdparse import cmd_line_parser
from lib.core.data import logger, conf, KB
from lib.core.option import init
from abc import ABC
import copy
from lxml import etree
from jsonpath import jsonpath
import json
import string
import random
import argparse
from urllib.parse import urlparse,parse_qs
import time
class MyHTMLParser(HTMLParser, ABC):
    def __init__(self):
        super().__init__()
        self.tree = []
        self.tokenizer = []
        self.root = None
        temp = {
            "tagname": "",
            "content": "",
            "attibutes": []
        }

    def handle_starttag(self, tag, attrs):
        if len(self.tree) == 0:
            self.root = tag
        self.tree.append(
            {
                "tagname": tag,
                "content": "",
                "attibutes": attrs
            }
        )

    def handle_endtag(self, tag):
        if len(self.tree) > 0:
            r = self.tree.pop()
            self.tokenizer.append(r)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data):
        if self.tree:
            self.tree[-1]["content"] += data

    def handle_comment(self, data):
        self.tokenizer.append({
            "tagname": "#comment",
            "content": data,
            "attibutes": []
        })

    def getTokenizer(self):
        while len(self.tree):
            r = self.tree.pop()
            self.tokenizer.append(r)
        return self.tokenizer


def getParamsFromHtml(html):
    parse = MyHTMLParser()
    parse.feed(html)
    tokens = parse.getTokenizer()
    
    result = set()
    for token in tokens:
        tagname = token["tagname"].lower()
        if tagname == "input":
            for attibute in token["attibutes"]:
                key, value = attibute
                if key == "name":
                    result.add(value)
                    break
        elif tagname == "script":
            content = token["content"]
            try:
                nodes = pyjsparser.parse(content).get("body", [])
            except pyjsparser.pyjsparserdata.JsSyntaxError as e:
                return []
            result |=set(analyse_js(nodes))
    return list(result)

def random_UA():
    ua_list = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
        'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 '
        'Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/76.0.3809.100 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/68.0',
        'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0',
    ]
    return random.choice(ua_list)
        
def add_cmd_arg():
    parser = argparse.ArgumentParser(description='xss检测增加地址参数')
    parser.add_argument('-u',"--url",type=str,help='地址',default=None)
    parser.add_argument('-f',"--file_address",type=str,help='地址文件',default=None)
    args=parser.parse_args()
    return args
def get_able_xss_param(my_session,domain_url,data):#得到界面的有反射的参数
   # print("开始运行get_able_xss_param")
    able_param_inner=[]
    #data= {'exp': 'oooexpooo*', 'o': 'ooooooo*', 'l': 'ooolooo*', 'a': 'oooaooo*','exp1': 'oooexpooo*', 'o1': 'ooooooo*', 'l1': 'ooolooo*', 'a1': 'oooaooo*','l2': 'ooolooo*', 'a2': 'oooaooo*'}
    try:
        resp = my_session.get(domain_url,params=data, headers={"User-Agent":random_UA()}).text
    except Exception as e:
        print("网站无法访问！")
        return []
    for key,value in data.items():
        if value in resp:
            able_param_inner.append(key)
    return able_param_inner
            
def get_name_params(res):#得到input标签里的参数
    e=etree.HTML(res)
    name_params=set(e.xpath('//input/@name'))
    return name_params

def get__form_address(res):#得到form提交的地址
    e=etree.HTML(res)
    name_params=e.xpath('//form/@action')
    return name_params

def get_normal_xscan_params(s,url,res):#得到普通的参数
    params_10_number={}
    data={}
    params_data = {}
    parse_params={}
    able_xss_params=[]
    able_xss_url=[]
    
    #1 获取参数
    parse_params = set(getParamsFromHtml(res)) 
    RISK_PARAMS = {"id", 'action', 'type', 'm', 'callback', 'cb'} #常用高危参数
    domain_url=url.split("?")[0]
    query=urlparse(url).query#得到参数
    url_params=parse_qs(query)#转化为字典
    for key,walue in url_params.items():#取出参数
       url_params_key.append(key)
    parse_params = parse_params | RISK_PARAMS | set(url_params_key) - get_name_params(res)#得到常用参数和返回参数的并集
    print("普通参数是",parse_params)
   # 2.准备poc
    for key in parse_params:
        params_data[key] = "ooo"+key+"ooo*" #给每个参数配一个随机字符串
   # print(params_data)
    i=0
    for key,value in params_data.items():# 每10个参数放入字典中
       # print("开始放入字典")
        params_10_number[key]=value
        i=i+1
        if(len(params_10_number)==10 or i==len(params_data)):
            data=copy.deepcopy(params_10_number)
            params_10_number={}
            able_xss_params=able_xss_params+get_able_xss_param(s,domain_url,data)
            data={}
            time.sleep(2)
        
    for param in able_xss_params:
        able_xss_url.append(domain_url+"?"+param+"=ooo"+param+"ooo")
    print("能用的普通参数是",able_xss_params)
    print("能用的普通地址是",able_xss_url)
    return able_xss_url

def get_special_xscan_params(s,url,res):#得到form表格里的参数
    params_10_number={}
    data={}
    params_data = {}
    parse_params={}
    able_xss_params=[]
    form_address=[]
    new_address=[]
    able_xss_url=[]
    
    #1 获取参数
    domain_url = url.split("?")[0]
    parse_params = get_name_params(res)#得到input参数
    print("input参数是",parse_params)
    form_address=get__form_address(res)#得到form跳转地址
    print("form得到的地址是",form_address)
    domain_url_list=[]
    for address in form_address:
        if "http" in address:
            domain_url=address #如果form的地址是完整地址直接用http完整地址
            domain_url_list.append(domain_url)
        else:
           # print(str( domain_url.find("/")))
            if domain_url.count("/")>2:
                new_address=domain_url.split("/")
                domain_url=domain_url.replace("/"+new_address[len(new_address)-1],"")
                domain_url=domain_url+address
                domain_url_list.append(domain_url)
            else:
                domain_url=domain_url+address
                domain_url_list.append(domain_url)
                
        
   # 2.准备poc
    for key in parse_params:
            params_data[key] = "ooo"+key+"ooo*" #给每个参数配一个随机字符串
    for domain in domain_url_list:#取出一个提交地址
        print("form提交地址是",domain)
    # print(params_data)
        i=0
        for key,value in params_data.items():# 每4个参数放入字典中
           # print("放入的参数是",key)
            params_10_number[key]=value
            i=i+1
            if(len(params_10_number)==4 or i==len(params_data)):
                data=copy.deepcopy(params_10_number)
                params_10_number={}
                able_xss_params=able_xss_params+get_able_xss_param(s,domain,data)
                data={}
                time.sleep(2)
        
        for param in able_xss_params:
            able_xss_url.append(domain+"?"+param+"=ooo"+param+"ooo")
    print("能用的input参数是",able_xss_params)
    print("能用的input地址是",able_xss_url)
    return able_xss_url
    
    
def format_address(url):
    if url.find("//")==-1:#自动加http
        url="http://"+url
    if "?" in url:
        return url
    if(url[-1]=="/" or url[-1]=="\\"):#如果最后一位是斜杠
        url=url[:-1]
    return url


def possible_xss_url(s,urls):#判断页面是否有xss漏洞
    model1="@\"'<>@"
    model2="@\"'@"
    model3="@<>@"
    for url in urls:
        my_url=url.split('=')[0] 
        if get_request_return(s,my_url,model1):
            xss_result=my_url+"="+model1+"存在xss反射漏洞！"
            return  xss_result
        else:
             if get_request_return(s,my_url,model2):
                xss_result=my_url+"="+model2+"存在xss反射漏洞！"
                return  xss_result
             else:
                if get_request_return(s,my_url,model3):
                    xss_result=my_url+"="+model3+"js上可能存在xss反射漏洞！"
                    return  xss_result
                else:
                    xss_result=""
                    return  xss_result
def get_request_return(s,url,model):#判断给的参数是否在返回的页面里
    my_url=url+"="+model
    try:
        resp = s.get(my_url, headers={"User-Agent":random_UA()}).text
        time.sleep(2)
    except Exception as e:
        print(e)
        return False
    #比较model与返回值是否相同
    if model in resp:
        return True
    else:
        return False
def test():
    url="http://demo.testfire.net"
    print(url.find('/'))
    
def main():
    global url_params_key
    url=""
    url_params_key=[]
    total_url=[]
    xss_result=""
    url_list=""
    total_xss_result=[]
    url=add_cmd_arg().url
    if url!=None:
        url_list.append(url)
    else: 
        url_file_address=add_cmd_arg().file_address
        url_file_address=os.path.join(sys.path[0],'test.txt')
        print(url_file_address)
        with open(url_file_address, 'r',encoding='utf-8' ) as f:
            url_list=(f.read().strip()).split('\n')  
    print(url_list)
    for url in url_list:
        print(url)
        url=url.strip()
        url=format_address(url)
        #print(url)
        try:
            res=requests.get(url).text
        except Exception as e:
            print(e)
            print("网站无法访问！")
            continue
        if(res==""):
            print("网站无法访问！")
            continue
        requests.DEFAULT_RETRIES=5
        s = requests.session()
        s.keep_alive=False
        total_url= list(set(get_normal_xscan_params(s,url,res)+get_special_xscan_params(s,url,res)))
        print(total_url)
        xss_result=possible_xss_url(s,total_url)
        if xss_result!="" and xss_result !=None:
            print(xss_result)
            total_xss_result.append(xss_result)

        

    print("总共找到如下地址xss",total_xss_result)

    #验证是否可能存在漏洞

    #resp = s.get(domain_url,params=params_data, headers={"User-Agent":random_UA()}).text
   
    #     #生成测试链接
    #     new_params=list(parse_params)
    #     for payload in payloads:
    #         for param in new_params:
    #            payload_url.append(url.split("?")[0]+"?"+param+"="+payload)
    # parse = MyHTMLParser()
    # parse.feed(t)
    # tokens = parse.getTokenizer()
    # print(tokens)
    # with open( 'test.txt', 'w',encoding='utf-8' ) as f:
    #     f.write(resp) 
    
if __name__ == '__main__':
    main()
