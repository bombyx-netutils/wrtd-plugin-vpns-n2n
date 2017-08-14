#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import re
import pwd
import grp
import time
import signal
import shutil
import socket
import logging
import ipaddress
import netifaces
import subprocess
from collections import OrderedDict
from gi.repository import Gio


def get_plugin_list():
    return [
        "n2n",
    ]


def get_plugin(name):
    if name == "n2n":
        return _PluginObject()
    else:
        assert False


class _PluginObject:

    def init2(self, instanceName, cfg, tmpDir, varDir, bridgePrefix, l2DnsPort, clientAddFunc, clientChangeFunc, clientRemoveFunc):
        assert instanceName == ""
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)

        self.bridge = _VirtualBridge(self, bridgePrefix, l2DnsPort, clientAddFunc, clientChangeFunc, clientRemoveFunc)
        self.n2nSupernodeProc = None

    def start(self):
        self._runN2nSupernode()
        self.bridge._runN2nEdgeNode()
        self.bridge._runDnsmasq()

    def stop(self):
        self.bridge._stopDnsmasq()
        self.bridge._stopN2nEdgeNode()
        self._stopN2nSupernode()

    def get_bridge(self):
        assert self.n2nSupernodeProc is not None
        assert self.bridge.edgeProc is not None
        return self.bridge

    def get_wan_service(self):
        ret = dict()
        ret["firewall_allow_list"] = []
        ret["firewall_allow_list"].append("udp dport 7654")
        return ret

    def generate_client_script(self, ip, ostype):
        if ostype == "linux":
            selfdir = os.path.dirname(os.path.realpath(__file__))
            buf = ""
            with open(os.path.join(selfdir, "client-script-linux.sh.in")) as f:
                buf = f.read()
            buf = buf.replace("@client_key@", "123456")                     # fixme
            buf = buf.replace("@super_node_ip@", ip)
            buf = buf.replace("@super_node_port@", str(7654))
            return ("client-script.sh", buf)
        elif ostype == "win32":
            assert False            # fixme, should create a bat script show it is not supported
        else:
            assert False

    def _runN2nSupernode(self):
        supernodeLogFile = os.path.join(self.tmpDir, "supernode.log")
        cmd = "/usr/sbin/supernode -f >%s 2>%s" % (supernodeLogFile, supernodeLogFile)
        self.n2nSupernodeProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

    def _stopN2nSupernode(self):
        if self.n2nSupernodeProc is not None:
            self.n2nSupernodeProc.terminate()
            self.n2nSupernodeProc.wait()
            self.n2nSupernodeProc = None


class _VirtualBridge:

    def __init__(self, pObj, prefix, l2DnsPort, clientAddFunc, clientChangeFunc, clientRemoveFunc):
        assert prefix[1] == "255.255.255.0"

        self.pObj = pObj
        self.l2DnsPort = l2DnsPort
        self.clientAddFunc = clientAddFunc
        self.clientChangeFunc = clientChangeFunc
        self.clientRemoveFunc = clientRemoveFunc

        self.brname = "wrtd-vpns-n2n"
        self.brnetwork = ipaddress.IPv4Network(prefix[0] + "/" + prefix[1])

        self.brip = ipaddress.IPv4Address(prefix[0]) + 1
        self.dhcpRange = (self.brip + 1, self.brip + 49)

        self.edgeProc = None

        self.myhostnameFile = os.path.join(self.pObj.tmpDir, "dnsmasq.myhostname")
        self.selfHostFile = os.path.join(self.pObj.tmpDir, "dnsmasq.self")
        self.hostsDir = os.path.join(self.pObj.tmpDir, "hosts.d")
        self.leasesFile = os.path.join(self.pObj.tmpDir, "dnsmasq.leases")
        self.pidFile = os.path.join(self.pObj.tmpDir, "dnsmasq.pid")
        self.dnsmasqProc = None
        self.leaseMonitor = None
        self.lastScanRecord = None

    def get_name(self):
        return self.brname

    def get_bridge_id(self):
        return "bridge-%s" % (self.brip)

    def get_prefix(self):
        return (str(self.brnetwork.network_address), str(self.brnetwork.netmask))

    def _runN2nEdgeNode(self):
        edgeLogFile = os.path.join(self.pObj.tmpDir, "edge.log")

        cmd = "/usr/sbin/edge -f "
        cmd += "-l 127.0.0.1:7654 "
        cmd += "-r -a %s -s %s " % (self.brip, self.brnetwork.netmask)
        cmd += "-d wrtd-vpns-n2n "
        cmd += "-c vpn "
        cmd += "-k 123456 "
        cmd += "-u %d -g %d " % (pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nobody").gr_gid)
        cmd += ">%s 2>%s" % (edgeLogFile, edgeLogFile)
        self.edgeProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

        while "wrtd-vpns-n2n" not in netifaces.interfaces():
            time.sleep(1.0)

    def _stopN2nEdgeNode(self):
        if self.edgeProc is not None:
            self.edgeProc.terminate()
            self.edgeProc.wait()
            self.edgeProc = None

    def on_source_add(self, source_id):
        with open(os.path.join(self.hostsDir, source_id), "w") as f:
            f.write("")

    def on_source_remove(self, source_id):
        os.unlink(os.path.join(self.hostsDir, source_id))

    def on_host_add(self, source_id, ip_data_dict):
        fn = os.path.join(self.hostsDir, source_id)
        itemDict = _Util.dnsmasqHostFileToOrderedDict(fn)
        bChanged = False

        for ip, data in ip_data_dict.items():
            if ip in itemDict:
                if "hostname" in data:
                    if itemDict[ip] != data["hostname"]:
                        itemDict[ip] = data["hostname"]
                        bChanged = True
                else:
                    del itemDict[ip]
                    bChanged = True
            else:
                if "hostname" in data:
                    itemDict[ip] = data["hostname"]
                    bChanged = True

        if bChanged:
            _Util.dictToDnsmasqHostFile(itemDict, fn)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_change(self, source_id, ip_data_dict):
        self.on_host_add(source_id, ip_data_dict)

    def on_host_remove(self, source_id, ip_list):
        fn = os.path.join(self.hostsDir, source_id)
        itemDict = _Util.dnsmasqHostFileToOrderedDict(fn)
        bChanged = False

        for ip in ip_list:
            if ip in itemDict:
                del itemDict[ip]
                bChanged = True

        if bChanged:
            _Util.dictToDnsmasqHostFile(itemDict, fn)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_refresh(self, source_id, ip_data_dict):
        fn = os.path.join(self.hostsDir, source_id)
        itemDict = _Util.dnsmasqHostFileToDict(fn)

        itemDict2 = dict()
        for ip, data in ip_data_dict.items():
            if "hostname" in data:
                itemDict2[ip] = data["hostname"]

        if itemDict != itemDict2:
            _Util.dictToDnsmasqHostFile(itemDict2, fn)
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def _runDnsmasq(self):
        # myhostname file
        with open(self.myhostnameFile, "w") as f:
            f.write("%s %s\n" % (self.brip, socket.gethostname()))

        # make hosts directory
        os.mkdir(self.hostsDir)

        # create empty leases file
        with open(self.leasesFile, "w") as f:
            f.write("")

        # generate dnsmasq config file
        buf = ""
        buf += "strict-order\n"
        buf += "bind-interfaces\n"                                       # don't listen on 0.0.0.0
        buf += "interface=%s\n" % (self.brname)
        buf += "except-interface=lo\n"                                   # don't listen on 127.0.0.1
        buf += "user=root\n"
        buf += "group=root\n"
        buf += "\n"
        buf += "dhcp-authoritative\n"
        buf += "dhcp-range=%s,%s,%s,360\n" % (self.dhcpRange[0], self.dhcpRange[1], self.brnetwork.netmask)
        buf += "dhcp-option=option:T1,180\n"                             # strange that dnsmasq's T1=165s, change to 180s which complies to RFC
        buf += "dhcp-leasefile=%s\n" % (self.leasesFile)
        buf += "\n"
        buf += "domain-needed\n"
        buf += "bogus-priv\n"
        buf += "no-hosts\n"
        buf += "server=127.0.0.1#%d\n" % (self.l2DnsPort)
        buf += "addn-hosts=%s\n" % (self.hostsDir)                       # "hostsdir=" only adds record, no deletion, so not usable
        buf += "addn-hosts=%s\n" % (self.myhostnameFile)                 # we use addn-hosts which has no inotify, and we send SIGHUP to dnsmasq when host file changes
        buf += "\n"
        cfgf = os.path.join(self.pObj.tmpDir, "dnsmasq.conf")
        with open(cfgf, "w") as f:
            f.write(buf)

        # run dnsmasq process
        cmd = "/usr/sbin/dnsmasq"
        cmd += " --keep-in-foreground"
        cmd += " --conf-file=\"%s\"" % (cfgf)
        cmd += " --pid-file=%s" % (self.pidFile)
        self.dnsmasqProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

        # monitor dnsmasq lease file
        self.leaseMonitor = Gio.File.new_for_path(self.leasesFile).monitor(0, None)
        self.leaseMonitor.connect("changed", self._dnsmasqLeaseChanged)
        self.lastScanRecord = []

    def _stopDnsmasq(self):
        self.lastScanRecord = None
        if self.leaseMonitor is not None:
            self.leaseMonitor.cancel()
            self.leaseMonitor = None
        if self.dnsmasqProc is not None:
            self.dnsmasqProc.terminate()
            self.dnsmasqProc.wait()
            self.dnsmasqProc = None
        _Util.forceDelete(self.pidFile)
        _Util.forceDelete(self.leasesFile)
        _Util.forceDelete(self.hostsDir)
        _Util.forceDelete(self.myhostnameFile)

    def _dnsmasqLeaseChanged(self, monitor, file, other_file, event_type):
        if event_type != Gio.FileMonitorEvent.CHANGED:
            return

        try:
            newLeaseList = _Util.readDnsmasqLeaseFile(self.leasesFile)

            addList = []
            changeList = []
            removeList = []
            for item in newLeaseList:
                item2 = self.___dnsmasqLeaseChangedFind(item, self.lastScanRecord)
                if item2 is not None:
                    if item[1] != item2[1] or item[3] != item2[3]:      # mac or hostname change
                        changeList.append(item)
                else:
                    addList.append(item)
            for item in self.lastScanRecord:
                if self.___dnsmasqLeaseChangedFind(item, newLeaseList) is None:
                    removeList.append(item)

            if len(addList) > 0:
                ipDataDict = dict()
                for expiryTime, mac, ip, hostname, clientId in addList:
                    self.__dnsmasqLeaseChangedAddToIpDataDict(ipDataDict, ip, mac, hostname)
                    if hostname != "":
                        self.pObj.logger.info("Client %s(IP:%s, MAC:%s) appeared." % (hostname, ip, mac))
                    else:
                        self.pObj.logger.info("Client %s(%s) appeared." % (ip, mac))
                self.clientAddFunc(self.get_bridge_id(), ipDataDict)

            if len(changeList) > 0:
                ipDataDict = dict()
                for expiryTime, mac, ip, hostname, clientId in changeList:
                    self.__dnsmasqLeaseChangedAddToIpDataDict(ipDataDict, ip, mac, hostname)
                    # log is not needed for client change
                self.clientChangeFunc(self.get_bridge_id(), ipDataDict)

            if len(removeList) > 0:
                ipList = [x[2] for x in removeList]
                self.clientRemoveFunc(self.get_bridge_id(), ipList)
                for expiryTime, mac, ip, hostname, clientId in removeList:
                    if hostname != "":
                        self.pObj.logger.info("Client %s(IP:%s, MAC:%s) disappeared." % (hostname, ip, mac))
                    else:
                        self.pObj.logger.info("Client %s(%s) disappeared." % (ip, mac))

            self.lastScanRecord = newLeaseList
        except Exception as e:
            self.pObj.logger.error("Lease scan failed", exc_info=True)      # fixme

    def ___dnsmasqLeaseChangedFind(self, item, leaseList):
        for item2 in leaseList:
            if item2[2] == item[2]:     # compare by ip
                return item2
        return None

    def __dnsmasqLeaseChangedAddToIpDataDict(self, ipDataDict, ip, mac, hostname):
        ipDataDict[ip] = dict()
        ipDataDict[ip]["wakeup-mac"] = mac
        if hostname != "":
            ipDataDict[ip]["hostname"] = hostname


class _Util:

    @staticmethod
    def forceDelete(filename):
        if os.path.islink(filename):
            os.remove(filename)
        elif os.path.isfile(filename):
            os.remove(filename)
        elif os.path.isdir(filename):
            shutil.rmtree(filename)

    @staticmethod
    def readDnsmasqLeaseFile(filename):
        """dnsmasq leases file has the following format:
             1108086503   00:b0:d0:01:32:86 142.174.150.208 M61480    01:00:b0:d0:01:32:86
             ^            ^                 ^               ^         ^
             Expiry time  MAC address       IP address      hostname  Client-id

           This function returns [(expiry-time,mac,ip,hostname,client-id), (expiry-time,mac,ip,hostname,client-id)]
        """

        pattern = "([0-9]+) +([0-9a-f:]+) +([0-9\.]+) +(\\S+) +(\\S+)"
        ret = []
        with open(filename, "r") as f:
            for line in f.read().split("\n"):
                m = re.match(pattern, line)
                if m is None:
                    continue
                expiryTime = m.group(1)
                mac = m.group(2)
                ip = m.group(3)
                hostname = "" if m.group(4) == "*" else m.group(4)
                clientId = "" if m.group(5) == "*" else m.group(5)
                ret.append((expiryTime, mac, ip, hostname, clientId))
        return ret

    @staticmethod
    def dnsmasqHostFileToDict(filename):
        ret = dict()
        with open(filename, "r") as f:
            for line in f.read().split("\n"):
                if line.startswith("#") or line.strip() == "":
                    continue
                t = line.split(" ")
                ret[t[0]] = t[1]
        return ret

    @staticmethod
    def dnsmasqHostFileToOrderedDict(filename):
        ret = OrderedDict()
        with open(filename, "r") as f:
            for line in f.read().split("\n"):
                if line.startswith("#") or line.strip() == "":
                    continue
                t = line.split(" ")
                ret[t[0]] = t[1]
        return ret

    @staticmethod
    def dictToDnsmasqHostFile(ipHostnameDict, filename):
        with open(filename, "w") as f:
            for ip, hostname in ipHostnameDict.items():
                f.write(ip + " " + hostname + "\n")
