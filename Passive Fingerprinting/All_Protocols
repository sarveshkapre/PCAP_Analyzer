#!/usr/bin/python
from scapy.all import *
import re
from impacket import *

IPProtocols = {
    0: 'IP', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IP-ENCAP', 56: 'TLSP', 133: 'FC', 6: 'TCP', 8: 'EGP', 137: 'MPLS-IN-IP', 138: 'MANET', 139: 'HIP', 12: 'PUP', 17: 'UDP', 20: 'HMP', 22: 'XNS-IDP', 132: 'SCTP', 27: 'RDP', 29: 'ISO-TP4', 5: 'ST', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 41: 'IPV6', 43: 'IPV6-ROUTE', 44: 'IPV6-FRAG',
    45: 'IDRP', 46: 'RSVP', 47: 'GRE', 136: 'UDPLITE', 50: 'IPSEC-ESP', 51: 'IPSEC-AH', 9: 'IGP', 57: 'SKIP', 58: 'IPV6-ICMP', 59: 'IPV6-NONXT', 60: 'IPV6-OPTS', 73: 'RSPF', 81: 'VMTP', 88: 'EIGRP', 89: 'OSPFIGP', 93: 'AX.25', 94: 'IPIP', 97: 'ETHERIP', 98: 'ENCAP', 103: 'PIM', 108: 'IPCOMP', 112: 'VRRP', 115: 'L2TP', 124: 'ISIS'}


pcap_file = "<pcap file location on your PC"

a = rdpcap(pcap_file)

x = 0
while x < len(a):
    raw_packet = str(a[x].summary())
    if raw_packet.count("IP") > 0:
        IPvar = (str(re.findall('\\bIPv6\\b', raw_packet)))
        if IPvar.count("IPv6") > 0:
            pass
        else:
            raw_packet = str(a[x].command())
            #print(raw_packet)
            IPnum = a[x][IP].proto
            list = []
            list.append("| PACKET " + str(x + 1) + " |   ")
            list.append("Source IP: " + str(a[x][IP].src + "    "))
            list.append("Destination IP: " + str(a[x][IP].dst + "    "))
            list.append("Protocol: " + str(IPProtocols[IPnum]) + "    ")
            list.append("Dest MAC: " + str(a[x][Ether].dst) + "    ")
            list.append("Src MAC: " + str(a[x][Ether].src) + "    ")
            list.append("IP version: " + str(a[x][IP].version) + "    ")
            list.append("Source Port: " + str(a[x][IP].sport) + "    ")
            list.append("Destination Port: " + str(a[x][IP].dport) + "    ")
            #list.append("TTL: " + str(a[x][IP].ttl) + "    ")
            modifylist = ''.join(list)
            print(modifylist)
    x += 1
