# -*- coding: utf8 -*-
__author__ = 'Viktor Winkelmann'


from TCPStream import *
from UDPStream import *
import socket
import os
import sys
import dpkt
import pandas as pd

# Workaround to get access to pcap packet record capture length field
def myIter(self):
    while True:
        buf = self._Reader__f.read(dpkt.pcap.PktHdr.__hdr_len__)
        if not buf:
            break
        hdr = self._Reader__ph(buf)
        buf = self._Reader__f.read(hdr.caplen)
        yield (hdr.tv_sec + (hdr.tv_usec / 1000000.0), hdr.caplen == hdr.len, buf)

class StreamBuilder:
    def __init__(self, pcapfile = None, **kwargs):
        self.tcpStreams = []
        self.udpStreams = []
        self.UDP_TIMEOUT = 120
        self.VERIFY_CHECKSUMS = True   # Might need to be disabled if Checksum Offloading
                                        # was used on the capturing NIC

        if 'udpTimeout' in kwargs:
            self.UDP_TIMEOUT = kwargs['udpTimeout']

        if 'verifyChecksums' in kwargs:
            self.VERIFY_CHECKSUMS = kwargs['verifyChecksums']

        self.__parsePcapfile(pcapfile)


    # Verify Layer3/4 Checksums, see dpkt/ip.py __str__ method
    @classmethod
    def __verify_checksums(cls, ippacket):
        if dpkt.in_cksum(ippacket.pack_hdr() + str(ippacket.opts)) != 0:
            return False

        if (ippacket.off & (dpkt.ip.IP_MF | dpkt.ip.IP_OFFMASK)) != 0:
            return True

        p = str(ippacket.data)
        s = dpkt.struct.pack('>4s4sxBH', ippacket.src, ippacket.dst,
                             ippacket.p, len(p))
        s = dpkt.in_cksum_add(0, s)
        s = dpkt.in_cksum_add(s, p)
        return dpkt.in_cksum_done(s) == 0

    def __parsePcapfile(self, pcapfile):
        if pcapfile is None:
            return


        with open(pcapfile, 'rb') as pcap:
            dpkt.pcap.Reader.__iter__ = myIter
            packets = dpkt.pcap.Reader(pcap)
            caplenError = False

            fsize = float(os.path.getsize(pcapfile))
            progress = -1

            tcp_packets = []
            udp_packets = []
            openTcpStreams = []
            openUdpStreams = []

            print '  Size of file %s: %.2f mb' % (pcapfile, fsize / 1000000)
            for packetNumber, (ts, complete, rawpacket) in enumerate(packets, 1):

                if not complete:
                    caplenError = True


                pos = int((pcap.tell() / fsize) * 100)
                if pos > progress:
                    sys.stdout.write("\r\t%d%%" % (pos,))
                    sys.stdout.flush()
                    progress = pos
                    #if progress > 15: break

                eth = dpkt.ethernet.Ethernet(rawpacket)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip = eth.data

                if self.VERIFY_CHECKSUMS and not self.__verify_checksums(ip):
                    continue


                packet = ip.data
                if ip.p == dpkt.ip.IP_PROTO_TCP:

                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    src_port = packet.sport
                    dst_port = packet.dport
                    key = frozenset({src_ip, dst_ip, src_port, dst_port})
                    tcp_packets.append({'key': key,
                                        'src_ip': src_ip, "dst_ip": dst_ip,
                                        'src_port': src_port, 'dst_port': dst_port,
                                        'packetNumber': packetNumber,
                                        'ts': ts, 'packet': packet})



                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    if len(packet.data) == 0:
                        continue

                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    src_port = packet.sport
                    dst_port = packet.dport
                    key = frozenset({src_ip, dst_ip, src_port, dst_port})
                    udp_packets.append({'key': key,
                                        'src_ip': src_ip, "dst_ip": dst_ip,
                                        'src_port': src_port, 'dst_port': dst_port,
                                        'packetNumber': packetNumber,
                                        'ts': ts, 'packet': packet})

            if len(tcp_packets) > 0:
                df_tcp = pd.DataFrame(tcp_packets)
                df_tcp["stream_id"] = pd.Categorical(df_tcp['key']).codes
                for stream_id, group in df_tcp.groupby("stream_id"):
                    tcpStream = TCPStream(group["src_ip"].values[0], group["src_port"].values[0],
                                          group["dst_ip"].values[0], group["dst_port"].values[0],
                                          group['packetNumber'].min(), pcapfile)

                    for packet, ts in zip(group["packet"].values, group["ts"].values):
                        tcpStream.addPacket(packet)
                    self.tcpStreams.append(tcpStream)

            if len(udp_packets) > 0:
                df_udp = pd.DataFrame(udp_packets)
                df_udp["stream_id"] = pd.Categorical(df_udp['key']).codes
                for stream_id, group in df_udp.groupby("stream_id"):
                    udpStream = UDPStream(group["src_ip"].values[0], group["src_port"].values[0],
                                          group["dst_ip"].values[0], group["dst_port"].values[0],
                                          group['packetNumber'].min(), pcapfile)

                    used_packets = []
                    lastSeen_ts = group["ts"].values[0]
                    for packet, ts, packetNumber in zip(group["packet"].values, group["ts"].values, group["packetNumber"].values):
                        if ts - lastSeen_ts > self.UDP_TIMEOUT:
                            self.udpStreams.append(udpStream)
                            sub_group = group[~group["packetNumber"].isin(used_packets)]
                            udpStream = UDPStream(sub_group["src_ip"].values[0], sub_group["src_port"].values[0],
                                                  sub_group["dst_ip"].values[0], sub_group["dst_port"].values[0],
                                                  sub_group['packetNumber'].min(), pcapfile)
                            udpStream.addPacket(packet, ts)
                            used_packets.append(packetNumber)
                        else:
                            # add packet to currently referenced udpStream
                            udpStream.addPacket(packet, ts)
                            used_packets.append(packetNumber)

                    self.udpStreams.append(udpStream)

