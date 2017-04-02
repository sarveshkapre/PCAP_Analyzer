#!/usr/bin/python
from scapy.all import *

# Change the path of the output file according to your system
MAC_OS_X = "C:/Users/sarve/Desktop/pcaps/MAC_OS_X.txt"
# Change the location of pcap file where you have stored it on your PC
pcap_file = "C:/Users/sarve/Desktop/pcaps/sample.pcapng"

f1 = open(MAC_OS_X, 'a+')

try:
    print('[+] Reading and parsing pcap file: %s' % pcap_file)
    a = rdpcap(pcap_file)
    #print(a)
except Exception as e:
    print('Something went wrong while opening/reading the pcap file.' '\n\nThe error message is: %s' % e)
    exit(0)

#print(len(a))
x = 0
while x < len(a):

    # Re-create the entire packet from the pcap file and then write it to our file
    #print(a[x].command())
    #f1.write(a[x].command())
    raw_packet = str(a[x].command())
    if raw_packet.count("Mac OS X") > 0:
        print("--------------")
        print("|  PACKET " + str(x + 1) + "  |")
        print("--------------")
        print("Operating System Details")
        print("Name: MAC OS X")
        n = raw_packet.find("Mac OS X")
        m = n+17
        version = raw_packet[n:m]
        print("Version: " +version)
        f1.write("-------------")
        f1.write("\n")
        f1.write("|  PACKET " + str(x + 1) + " |")
        f1.write("\n")
        f1.write("-------------")
        f1.write("\n")
        f1.write("MAC Operating System")
        f1.write("\n")
        f1.write("MAC Operating Version" + version)
        f1.write("\n")
    x += 1
f1.close()
