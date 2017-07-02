#!/usr/bin/python3

import sys
import json
import socket


serverFile = "/tmp/wrtd/vpns-n2n/cmd.socket"        # fixme

data = dict()
if sys.argv[1] == "add":
    data["cmd"] = "add-or-change"
elif sys.argv[1] == "old":
    data["cmd"] = "add-or-change"
elif sys.argv[1] == "del":
    data["cmd"] = "remove"
else:
    sys.exit(0)    # ignore unsupported action according to dnsmasq's manpage

data["mac"] = sys.argv[2]
data["ip"] = sys.argv[3]
data["hostname"] = sys.argv[4]

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.sendto(json.dumps(data).encode("utf-8"), serverFile)
sock.close()
