#!/usr/bin/python
from scapy.all import *

# Change the path of the output file according to your system
pcap_output_file = "C:/../../../pcap_output_file.txt"
# Change the location of pcap file where you have stored it on your PC
pcap_file = "C:/../../../http_google.pcap"

f1 = open(pcap_output_file, 'a+')

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
    # print summary of pcap file
    print("___________________")
    f1.write("___________________")
    print("|  PACKET" + str(x+1) + "  |")
    f1.write("|  PACKET" + str(x+1) + "  |")
    f1.write("___________________")
    print("___________________")
    print(a[x].summary())
    f1.write(a[x].summary())
    f1.write("\n")
    f1.write("\n")
    f1.write("\n")
    # If we want to see more of the packet contents then execute show() command
    print("show")
    print(a[x].show())


    # Re-create the entire packet from the pcap file and then write it to our file
    print("command")
    print(a[x].command())
    f1.write(a[x].command())
    f1.write("\n")
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

    print("Source Port:")
    f1.write("Source Port:")
    print(a[x][TCP].sport)
    f1.write(str(a[x][TCP].sport))
    f1.write("\n")
    print("")

    print("Destination Port:")
    f1.write("Destination Port:")
    print(a[x][TCP].dport)
    f1.write(str(a[x][TCP].dport))
    f1.write("\n")
    print("")

    print("Window Size in TCP connection:")
    f1.write("Window Size in TCP connection:")
    os = a[x][TCP].window
    print(os)
    f1.write(str(os))
    f1.write("\n")
    print("")

    if os == 8192:
        print("It is either Windows 7 or 8 or 10")
        f1.write("It is either Windows 7 or 8 or 10")
        f1.write("\n")
        print("")
    print("_________________________________________")
    f1.write("_______________________________________________________________________________________________________")
    f1.write("\n")
    f1.write("_______________________________________________________________________________________________________")
    f1.write("\n")
    f1.write("\n")
    print("_________________________________________")
    x += 1

f1.close()
