#!/usr/bin/python
from scapy.all import *

# Change the path of the output file according to your system
home1 = "C:/../../../../home1.txt"
# Change the location of pcap file where you have stored it on your PC
pcap_file = "C:/../../../home1.pcapng"

f1 = open(home1, 'w+')

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

        print("TTL:")
        f1.write("TTL:")
        print(a[x][IP].ttl)
        f1.write(str(a[x][IP].ttl))
        f1.write("\n")
        print("")

        print("Protocol:")
        f1.write("Protocol:")
        print(a[x][IP].proto)
        f1.write(str(a[x][IP].proto))
        f1.write("\n")
        print("")

        print("Source IP:")
        print(str(a[x][IP].src))
        print("")

        print("Destination IP:")
        f1.write("Destination IP:")
        print(a[x][IP].dst)
        f1.write(str(a[x][IP].dst))
        f1.write("\n")
        print("")


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

    elif raw_packet.count("Windows") > 0:
        print("--------------")
        print("|  PACKET " + str(x + 1) + "  |")
        print("--------------")

        f1.write("-------------")
        f1.write("\n")
        f1.write("|  PACKET " + str(x + 1) + " |")
        f1.write("\n")
        f1.write("-------------")
        f1.write("\n")

        try:
            print("TTL:")
            f1.write("TTL:")
            print(a[x][IP].ttl)
            f1.write(str(a[x][IP].ttl))
            f1.write("\n")
            print("")
        except Exception as e:
            print("Unable to find ttl")

        try:
            print("Protocol:")
            f1.write("Protocol:")
            print(a[x][IP].proto)
            f1.write(str(a[x][IP].proto))
            f1.write("\n")
            print("")
        except Exception as e:
            print("Unable to find protocol")

        try:
            print("Source IP:")
            f1.write("Source IP:")
            print(a[x][IP].src)
            f1.write(str(a[x][IP].src))
            f1.write("\n")
            print("")
            print("Destination IP:")
            f1.write("Destination IP:")
            print(a[x][IP].dst)
            f1.write(str(a[x][IP].dst))
            f1.write("\n")
            print("")

            n = raw_packet.find("USER-AGENT")
            m = raw_packet.find("\n")
            Details = raw_packet[n:m]
            print("Details: " + Details)
            f1.write(str(Details))
            f1.write("\n")
            print("Windows Operating system")
            f1.write("Windows Operating System")
            f1.write("\n")
            f1.write("\n")
        except Exception as e:
            print("Unable to extract source address")

    else:
        try:
            n = raw_packet.find("ARP")
            m = raw_packet.find("op=2")
            o = raw_packet.find("Padding")
            if n > 0 and m > 0 and o > 0:
                # print(x)
                # print(hexdump(a[x]))
                # print(ls(a[x]))

                print("--------------")
                print("|  PACKET " + str(x + 1) + "  |")
                print("--------------")

                f1.write("-------------")
                f1.write("\n")
                f1.write("|  PACKET " + str(x + 1) + " |")
                f1.write("\n")
                f1.write("-------------")
                f1.write("\n")

                print("Mac address of router:")
                f1.write("Mac address of router: ")
                print(a[x][ARP].hwsrc)
                f1.write(a[x][ARP].hwsrc)
                f1.write("\n")
                print("IP address of router:")
                f1.write("IP address of router:")
                print(a[x][ARP].psrc)
                f1.write(a[x][ARP].psrc)
                f1.write("\n")
        except Exception as e:
            print("")

    x += 1
f1.close()
