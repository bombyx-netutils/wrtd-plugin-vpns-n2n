#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import pwd
import grp
import socket
import struct
import fcntl
import subprocess


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

    def init2(self, instanceName, cfg, tmpDir):
        assert instanceName == ""
        self.cfg = cfg
        self.tmpDir = tmpDir

        self.n2nSupernodeProc = None
        self.proc = None

    def start(self):
        self._runN2nSupernode()
        self._runN2nEdgeNode()

    def stop(self):
        self._stopN2nEdgeNode()
        self._stopN2nSupernode()

    def get_bridge(self):
        return None

    def interface_appear(self, bridge, ifname):
        if ifname == "wrt-lif-n2n":
            _Util.addInterfaceToBridge(bridge.get_name(), ifname)
            return True
        else:
            return False

    def interface_disappear(self, ifname):
        pass

    def _runN2nSupernode(self):
        supernodeLogFile = os.path.join(self.tmpDir, "n2n-supernode.log")
        cmd = "/usr/sbin/supernode -f >%s 2>%s" % (supernodeLogFile, supernodeLogFile)
        self.n2nSupernodeProc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

    def _stopN2nSupernode(self):
        if self.n2nSupernodeProc is not None:
            self.n2nSupernodeProc.terminate()
            self.n2nSupernodeProc.wait()
            self.n2nSupernodeProc = None

    def _runN2nEdgeNode(self):
        edgeLogFile = os.path.join(self.tmpDir, "n2n-edge.log")

        cmd = "/usr/sbin/edge -f "
        cmd += "-l 127.0.0.1:7654 "
        cmd += "-r "
        cmd += "-d wrt-lif-n2n "
        cmd += "-c vpn "
        cmd += "-k 123456 "
        cmd += "-u %d -g %d " % (pwd.getpwnam("nobody").pw_uid, grp.getgrnam("nobody").gr_gid)
        cmd += ">%s 2>%s" % (edgeLogFile, edgeLogFile)
        self.proc = subprocess.Popen(cmd, shell=True, universal_newlines=True)

    def _stopN2nEdgeNode(self, proc):
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None


class _Util:

    @staticmethod
    def addInterfaceToBridge(brname, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ifreq = struct.pack("16si", ifname, 0)
            ret = fcntl.ioctl(s.fileno(), 0x8933, ifreq)            # SIOCGIFINDEX
            ifindex = struct.unpack("16si", ret)[1]

            ifreq = struct.pack("16si", brname, ifindex)
            fcntl.ioctl(s.fileno(), 0x89a2, ifreq)                  # SIOCBRADDIF
        finally:
            s.close()
