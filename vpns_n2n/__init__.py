#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import re
import pwd
import grp
import time
import fcntl
import signal
import shutil
import socket
import struct
import logging
import ipaddress
import netifaces
import subprocess
from gi.repository import GLib
from gi.repository import GObject


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

    def init2(self, instanceName, cfg, tmpDir, varDir, bridgePrefix, l2DnsPort, clientAppearFunc, clientDisappearFunc, firewallAllowFunc):
        assert instanceName == ""
        self.cfg = cfg
        self.tmpDir = tmpDir
        self.firewallAllowFunc = firewallAllowFunc
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)

        self.bridge = _VirtualBridge(self, bridgePrefix, l2DnsPort, clientAppearFunc, clientDisappearFunc)
        self.n2nSupernodeProc = None

    def set_other_bridge_list(self, other_bridge_list):
        pass

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
        self.firewallAllowFunc("udp dport 7654")

    def _stopN2nSupernode(self):
        if self.n2nSupernodeProc is not None:
            self.n2nSupernodeProc.terminate()
            self.n2nSupernodeProc.wait()
            self.n2nSupernodeProc = None


class _VirtualBridge:

    def __init__(self, pObj, prefix, l2DnsPort, clientAppearFunc, clientDisappearFunc):
        assert prefix[1] == "255.255.255.0"

        self.pObj = pObj
        self.l2DnsPort = l2DnsPort
        self.clientAppearFunc = clientAppearFunc
        self.clientDisappearFunc = clientDisappearFunc

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
        self.leaseScanTimer = None
        self.lastScanRecord = None

    def get_name(self):
        return self.brname

    def get_bridge_id(self):
        return "bridge-%s" % (self.brip)

    def get_prefix(self):
        return (str(self.brnetwork.network_address), str(self.brnetwork.netmask))

    def get_subhost_ip_range(self):
        subhostIpRange = []
        i = 51
        while i + 49 < 255:
            subhostIpRange.append((str(self.brip + i), str(self.brip + i + 49)))
            i += 50
        return subhostIpRange

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

    def on_host_add_or_change(self, source_id, ip_data_dict):
        bChanged = False
        fn = os.path.join(self.hostsDir, source_id)
        with open(fn, "a") as f:
            for ip, data in ip_data_dict.items():
                if "hostname" in data:
                    f.write(ip + " " + data["hostname"] + "\n")
                    bChanged = True

        if bChanged:
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_remove(self, source_id, ip_list):
        fn = os.path.join(self.hostsDir, source_id)
        bChanged = False

        lineList = []
        with open(fn, "r") as f:
            lineList = f.read().rstrip("\n").split("\n")

        lineList2 = []
        for line in lineList:
            if line.split(" ")[0] not in ip_list:
                lineList2.append(line)
            else:
                bChanged = True

        if bChanged:
            with open(fn, "w") as f:
                for line in lineList2:
                    f.write(line + "\n")
            self.dnsmasqProc.send_signal(signal.SIGHUP)

    def on_host_refresh(self, source_id, ip_data_dict):
        fn = os.path.join(self.hostsDir, source_id)

        buf = ""
        with open(fn, "r") as f:
            buf = f.read()

        buf2 = ""
        for ip, data in ip_data_dict.items():
            if "hostname" in data:
                buf2 += ip + " " + data["hostname"] + "\n"

        if buf != buf2:
            with open(fn, "w") as f:
                f.write(buf2)
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

        self.lastScanRecord = set()
        self.leaseScanTimer = GObject.timeout_add_seconds(10, self._leaseScan)

    def _stopDnsmasq(self):
        if self.leaseScanTimer is not None:
            GLib.source_remove(self.leaseScanTimer)
            self.leaseScanTimer = None
            self.lastScanRecord = None
        if self.dnsmasqProc is not None:
            self.dnsmasqProc.terminate()
            self.dnsmasqProc.wait()
            self.dnsmasqProc = None
        _Util.forceDelete(self.pidFile)
        _Util.forceDelete(self.leasesFile)
        _Util.forceDelete(self.hostsDir)
        _Util.forceDelete(self.myhostnameFile)

    def _leaseScan(self):
        try:
            ret = set(_Util.readDnsmasqLeaseFile(self.leasesFile))

            # host disappear
            setDisappear = self.lastScanRecord - ret
            ipList = [x[1] for x in setDisappear]
            if len(ipList) > 0:
                self.clientDisappearFunc(self.get_bridge_id(), ipList)
                for mac, ip, hostname in setDisappear:
                    if hostname != "":
                        self.pObj.logger.info("Client %s(IP:%s, MAC:%s) disappeared." % (hostname, ip, mac))
                    else:
                        self.pObj.logger.info("Client %s(%s) disappeared." % (ip, mac))

            # host appear
            setAppear = ret - self.lastScanRecord
            ipDataDict = dict()
            for mac, ip, hostname in setAppear:
                ipDataDict[ip] = dict()
                if hostname != "":
                    ipDataDict[ip]["hostname"] = hostname
                    self.pObj.logger.info("Client %s(IP:%s, MAC:%s) appeared." % (hostname, ip, mac))
                else:
                    self.pObj.logger.info("Client %s(%s) appeared." % (ip, mac))
            if len(ipDataDict) > 0:
                self.clientAppearFunc(self.get_bridge_id(), ipDataDict)

            self.lastScanRecord = ret
        except:
            self.pObj.logger.error("Lease scan failed.", exc_info=True)
        finally:
            return True


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
    def addInterfaceToBridge(brname, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ifreq = struct.pack("16si", ifname.encode("ascii"), 0)
            ret = fcntl.ioctl(s.fileno(), 0x8933, ifreq)                    # SIOCGIFINDEX
            ifindex = struct.unpack("16si", ret)[1]

            ifreq = struct.pack("16si", brname.encode("ascii"), ifindex)
            fcntl.ioctl(s.fileno(), 0x89a2, ifreq)                          # SIOCBRADDIF
        finally:
            s.close()

    @staticmethod
    def readDnsmasqLeaseFile(filename):
        """dnsmasq leases file has the following format:
             1108086503   00:b0:d0:01:32:86 142.174.150.208 M61480    01:00:b0:d0:01:32:86
             ^            ^                 ^               ^         ^
             Expiry time  MAC address       IP address      hostname  Client-id

           This function returns [(mac,ip,hostname), (mac,ip,hostname)]
        """

        pattern = "[0-9]+ +([0-9a-f:]+) +([0-9\.]+) +(\\S+) +\\S+"
        ret = []
        with open(filename, "r") as f:
            for line in f.read().split("\n"):
                m = re.match(pattern, line)
                if m is None:
                    continue
                if m.group(3) == "*":
                    item = (m.group(1), m.group(2), "")
                else:
                    item = (m.group(1), m.group(2), m.group(3))
                ret.append(item)
        return ret
