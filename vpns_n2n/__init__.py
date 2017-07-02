#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import pwd
import grp
import time
import json
import signal
import shutil
import socket
import logging
import ipaddress
import netifaces
import subprocess
from gi.repository import GLib


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
        self.bridge._runCmdServer()

    def stop(self):
        self.bridge._stopCmdServer()
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

        self.serverFile = os.path.join(self.pObj.tmpDir, "cmd.socket")
        self.cmdSock = None
        self.cmdSockWatch = None

        self.myhostnameFile = os.path.join(self.pObj.tmpDir, "dnsmasq.myhostname")
        self.selfHostFile = os.path.join(self.pObj.tmpDir, "dnsmasq.self")
        self.hostsDir = os.path.join(self.pObj.tmpDir, "hosts.d")
        self.leasesFile = os.path.join(self.pObj.tmpDir, "dnsmasq.leases")
        self.pidFile = os.path.join(self.pObj.tmpDir, "dnsmasq.pid")
        self.dnsmasqProc = None

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

    def _runCmdServer(self):
        self.cmdSock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.cmdSock.bind(self.serverFile)
        self.cmdSockWatch = GLib.io_add_watch(self.cmdSock, GLib.IO_IN, self.__cmdServerWatch)

    def _stopCmdServer(self):
        if self.cmdSockWatch is not None:
            GLib.source_remove(self.cmdSockWatch)
            self.cmdSockWatch = None
        if self.cmdSock is not None:
            self.cmdSock.close()
            self.cmdSock = None

    def _runDnsmasq(self):
        selfdir = os.path.dirname(os.path.realpath(__file__))

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
        buf += "dhcp-script=%s\n" % (os.path.join(selfdir, "dhcp-script.py"))
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

    def _stopDnsmasq(self):
        if self.dnsmasqProc is not None:
            self.dnsmasqProc.terminate()
            self.dnsmasqProc.wait()
            self.dnsmasqProc = None
        _Util.forceDelete(self.pidFile)
        _Util.forceDelete(self.leasesFile)
        _Util.forceDelete(self.hostsDir)
        _Util.forceDelete(self.myhostnameFile)

    def __cmdServerWatch(self, source, cb_condition):
        try:
            buf = self.cmdSock.recvfrom(4096)[0].decode("utf-8")
            jsonObj = json.loads(buf)
            if jsonObj["cmd"] == "add-or-change":
                # notify lan manager
                data = dict()
                data[jsonObj["ip"]] = dict()
                if "hostname" in jsonObj:
                    data[jsonObj["ip"]]["hostname"] = jsonObj["hostname"]
                self.clientAppearFunc(self.get_bridge_id(), data)
            elif jsonObj["cmd"] == "remove":
                # notify lan manager
                data = [jsonObj["ip"]]
                self.clientDisappearFunc(self.get_bridge_id(), data)
            else:
                assert False
        except:
            self.pObj.logger.error("receive error", exc_info=True)       # fixme
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
