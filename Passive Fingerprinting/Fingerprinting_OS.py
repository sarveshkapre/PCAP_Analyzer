#!/usr/bin/python
from scapy.all import *

# Replace path to store pcap output file
pcap_output_file = "C:/../../../pcap_output_file.txt"

#Replace path with directory where you have stored your pcap file
pcap_file = "C:/../../../http_google.pcap"

f1 = open(pcap_output_file, 'a+')

print('[+] Reading and parsing pcap file: %s' + pcap_file)

#read the entire pcap and store it in list a
a = rdpcap(pcap_file)

#print summary of pcap file
print(a[0].summary())
f1.write(a[0].summary())
f1.write("\n")
# If we want to see more of the packet contents then execute show() command
print(a[0].show())

# Re-create the entire packet from the pcap file and then write it to our file
print(a[0].command())
f1.write(a[0].command())
f1.write("\n")

# Digging into layers by field
print("_________________________")
f1.write("\n")
print("|  Digging into Layers  |")
f1.write("\n")
print("_________________________")
f1.write("\n")
print("TTL:")
f1.write("TTL:")
print(a[0][IP].ttl)
f1.write(str(a[0][IP].ttl))
f1.write("\n")
print("")

print("Protocol:")
f1.write("Protocol:")
print(a[0][IP].proto)
f1.write(str(a[0][IP].proto))
f1.write("\n")
print("")

print("Source IP:")
print(str(a[0][IP].src))
print("")

print("Destination IP:")
f1.write("Destination IP:")
print(a[0][IP].dst)
f1.write(str(a[0][IP].dst))
f1.write("\n")
print("")

print("Source Port:")
f1.write("Source Port:")
print(a[0][TCP].sport)
f1.write(str(a[0][TCP].sport))
f1.write("\n")
print("")

print("Destination Port:")
f1.write("Destination Port:")
print(a[0][TCP].dport)
f1.write(str(a[0][TCP].dport))
f1.write("\n")
print("")

print("Window Size in TCP connection:")
f1.write("Window Size in TCP connection:")
os = a[0][TCP].window
print(os)
f1.write(str(os))
f1.write("\n")
print("")

if os == 8192:
    print("It is either Windows 7 or 8 or 10")
    f1.write("It is either Windows 7 or 8 or 10")
    f1.write("\n")
    print("")
f1.close()
