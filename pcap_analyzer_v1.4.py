#!/usr/bin/python

'''
Information Found
1.	Operating System
a.	Windows
b.	MAC
2.	Switch - Cisco
3.	Router - Cisco
4.	Services – Common Port numbers
5.	Protocols – ALL – Get more information from protocols
6.	Browser Information of machine - example - Google Chrome, it's version number, OS details etc
7.	Websites visited? User agents
8.	ICMP – number of hops – map of network traceroute
9.	TTL: 61 and OS is Linux, then there maybe 3 hops as TTL for Linux is 64

TO BE DONE
> save content in a file to current directory and use time function to name the file
> Process the file to remove recurring data
> categorize IP as local external multicast and broadcast
> Map of devices
'''

from scapy.all import *
#from testgui import *
from tkinter import *
import re
from impacket import *
from datetime import datetime
from tkinter import Tk, Label, Button
from tkinter.filedialog import askopenfilename

# print(x)
# print(hexdump(a[x]))
# print(ls(a[x]))

# List of common IP protocols

IPProtocols = {
                0: 'IP', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IP-ENCAP', 56: 'TLSP', 133: 'FC', 6: 'TCP', 8: 'EGP', 137: 'MPLS-IN-IP',
                138: 'MANET', 139: 'HIP', 12: 'PUP', 17: 'UDP', 20: 'HMP', 22: 'XNS-IDP', 132: 'SCTP', 27: 'RDP', 29: 'ISO-TP4',
                5: 'ST', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 41: 'IPV6', 43: 'IPV6-ROUTE', 44: 'IPV6-FRAG', 45: 'IDRP',
                46: 'RSVP', 47: 'GRE', 136: 'UDPLITE', 50: 'IPSEC-ESP', 51: 'IPSEC-AH', 9: 'IGP', 57: 'SKIP', 58: 'IPV6-ICMP',
                59: 'IPV6-NONXT', 60: 'IPV6-OPTS', 73: 'RSPF', 81: 'VMTP', 88: 'EIGRP', 89: 'OSPFIGP', 93: 'AX.25', 94: 'IPIP',
                97: 'ETHERIP', 98: 'ENCAP', 103: 'PIM', 108: 'IPCOMP', 112: 'VRRP', 115: 'L2TP', 124: 'ISIS'
              }
#print('6' in IPProtocols.values())
#print(IPProtocols[6])
#True
# List of common TCP port numbers to find out running services

TCPPorts = {
            20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 389: 'LDAP', 636: 'LDAPssl',
            137: 'NetBIOS Name Service NBNS', 138: "NetBios Datagram Service NBDS", 520: 'RIP', 161: 'SNMP', 179: 'BGP',
            445: 'SMB', 67: 'DHCP Bootpc', 68: 'DHCP Bootps', 49: 'TACACS', 88: 'Kerberos', 156: 'SQL Service', 162: 'SNMP Trap',
            530: 'RPC', 5060: 'SIP non encrypted', 5061: 'SIP encrypted'
            }


LARGE_FONT = ("Verdana", 12)

# class AutoScrollbar(Scrollbar):
#     # a scrollbar that hides itself if it's not needed.  only
#     # works if you use the grid geometry manager.
#     def set(self, lo, hi):
#         if float(lo) <= 0.0 and float(hi) >= 1.0:
#             # grid_remove is currently missing from Tkinter!
#             self.tk.call("grid", "remove", self)
#         else:
#             self.grid()
#         Scrollbar.set(self, lo, hi)
    # def pack(self, **kw):
    #     raise TclError, "cannot use pack with this widget"
    # def place(self, **kw):
    #     raise TclError, "cannot use place with this widget"

# def make_label(master, x, y, h, w, *args, **kwargs):
#     f = Frame(master, height=h, width=w)
#     f.pack_propagate(0)  # don't shrink
#     f.place(x=x, y=y)
#     label = Label(f, *args, **kwargs)
#     label.pack(fill=BOTH, expand=1)
#
#     canvas = Canvas(f, bg='#FFFFFF', width=300, height=300, scrollregion=(0, 0, 500, 500))
#     hbar = Scrollbar(f, orient=HORIZONTAL)
#     hbar.pack(side=BOTTOM, fill=X)
#     hbar.config(command=canvas.xview)
#     vbar = Scrollbar(f, orient=VERTICAL)
#     vbar.pack(side=RIGHT, fill=Y)
#     vbar.config(command=canvas.yview)
#
#     #canvas.create_text(text=storelist)
#     canvas.config(width=300, height=300)
#     canvas.config(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
#     canvas.pack(side=LEFT, expand=True, fill=BOTH)
#     root.mainloop()
#     return label

class PcapAnalyzer:
    def __init__(self, master):
        self.master = master
        master.title("PCAP ANALYZER")

        self.label = Label(master, text="Upload a PCAP file to analyze.\n The output will be stored in the same folder!", font= LARGE_FONT)
        self.label.pack(pady=250,padx=460)

        self.upload_button = Button(master, text="Upload", command=self.upload)
        self.upload_button.pack()

        self.start_button = Button(master, text="Start", command=master.quit)
        self.start_button.pack()

        self.close_button = Button(master, text="Close", command=master.quit)
        self.close_button.pack()

    def upload(self):

        ftypes = [('All file', "*.*")]
        ttl = "Title"
        dir1 = 'C:\\Users\sarve\Desktop\pcaps'
        root.fileName = askopenfilename(filetypes=ftypes, initialdir=dir1, title=ttl)


root = Tk()
my_gui = PcapAnalyzer(root)
root.mainloop()


def analyzepcap():

    #Read a pcap file by adding the path of the file below.
    # Enter proper extension - pcap files have - cap, pcap, pcapng etc.
    #pcap_file = "C:/Users/sarve/Desktop/pcaps/telnet.cap"
    pcap_file = root.fileName
    # Create a file and add date and time to it
    # Replace the file extnesion .csv to any that you want . for example ->   .txt
    filename = 'C:/Users/sarve/Desktop/pcaps/pcapfile-%s.txt'%datetime.now().strftime('%Y-%m-%d_%H_%M')
    f1 = open(filename, 'w+')

    try:
        #Read a pcap file and store it in variable a
        a = rdpcap(pcap_file)
        num_packets = len(a)
    except Exception as e:
        print('Something went wrong while opening/reading the pcap file.' '\n\nThe error message is: %s' % e)
        exit(0)

    # X denotes the packet number. Initially we will start with first packet denoted by 0.
    x = 0
    # Go through each packet and increment value of X after the loop

    while x < len(a):
        # Approach is to write a safe code
        # Hence value checking is done at every step using if statement
        #raw_packet = str(a[x].show())
        raw_packet = str(a[x].summary())
        if raw_packet.count("IP") > 0:
            # IPV6 packet format is diffrent from IPv4. Hence the below techniques to extract packet information wont work
            # Hence I filtered IPv6
            #IPvar = (str(re.findall('\\bIPv6\\b', raw_packet)))
            raw_packet = str(a[x].command())
            if raw_packet.count("IPv6") > 0:
                pass
            else:
                #raw_packet = str(a[x].command())
                #print(raw_packet)

                if raw_packet.count("proto") > 0:
                    IPnum = a[x][IP].proto
                    #print(IPnum)
                # All the packet information will be stored in the list
                list = []


                list.append("| PACKET " + str(x + 1) + " |   ")

                if raw_packet.count("src") > 0:
                    #print(raw_packet)
                    list.append("Source IP: " + str(a[x][IP].src) + "    ")
                if raw_packet.count("dst") > 0:
                    list.append("Destination IP: " + str(a[x][IP].dst) + "    ")

                # IP protocol information is available in the dictionary. it will lookup to find right protocol information
                # 'one' in d.values() True
                # If IP Protocol is not available then it will throw an exception.
                # Hence check whether value exists in dictionary
                _dict_value = IPnum in IPProtocols.keys()
                #print(_dict_value)
                if _dict_value is True:
                    list.append("Protocol: " + str(IPProtocols[IPnum]) + "    ")

                if raw_packet.count("dst") > 0:
                    list.append("Dest MAC: " + str(a[x][Ether].dst) + "    ")

                if raw_packet.count("src") > 0:
                    list.append("Src MAC: " + str(a[x][Ether].src) + "    ")

                if raw_packet.count("version") > 0:
                    list.append("IP version: " + str(a[x][IP].version) + "    ")

                # Few packets does not have source and destinationport numbers. Hence we check it here before calculating.
                # Else it will trigger an error
                if raw_packet.count("sport") > 0:
                    list.append("Source Port: " + str(a[x][IP].sport) + "    ")
                    port_info = a[x][IP].sport
                    #print(p)
                    # Port number information is available in the dictionary.
                    # It will lookup to find right service information
                    # Check whether value exists in dictionary
                    _dict_value = port_info in TCPPorts.keys()
                    #print(_dict_value)
                    if _dict_value is True:
                        list.append(str(TCPPorts[port_info]) + " service is running    ")

                if raw_packet.count("dport") > 0:
                    list.append("Destination Port: " + str(a[x][IP].dport) + "    ")
                    port_info = a[x][IP].dport
                    # Port number information is available in the dictionary.
                    # It will lookup to find right service information
                    # Check whether value exists in dictionary
                    _dict_value = port_info in TCPPorts.keys()
                    #print(_dict_value)
                    if _dict_value is True:
                        list.append(str(TCPPorts[port_info]) + " service is running    ")

                # Calculate the TTL
                list.append("TTL: " + str(a[x][IP].ttl) + "    ")

                if raw_packet.count("Mac OS X") > 0:
                    n = raw_packet.find("Mac OS X")
                    m = n + 17
                    version = raw_packet[n:m]
                    list.append("Operating System Details- Name: MAC OS X,  MAC Operating Version: " + version  + "    ")

                if raw_packet.count("Windows") > 0:
                    n = raw_packet.find("USER-AGENT")
                    m = raw_packet.find("\n")
                    Details = raw_packet[n:m]
                    list.append("Details: " + Details + "Windows Operating system     ")

                n = raw_packet.find("CDP")
                if n > 0:
                    list.append("CDP is used by the CISCO device   ")

                # List displays in an array format. Hence we join to remove unrequired characters
                modifylist = ''.join(list)
                list1.append(modifylist + "\n\n")
                # print(list)
                print(modifylist)


                #lb.insert(END, modifylist)
                f1.write(modifylist)
                f1.write("\n")
                f1.write("\n")

        # Router communication involves sending ARP request
        if raw_packet.count("ARP") > 0:
            raw_packet = str(a[x].command())
            # print(raw_packet)
            # All the packet information will be stored in the list
            list = []

            list.append("| PACKET " + str(x + 1) + " |   ")
            try:
                n = raw_packet.find("ARP")
                m = raw_packet.find("op=2")
                o = raw_packet.find("Padding")
                if n > 0 and m > 0 and o > 0:
                    list.append("Mac address of router: " + str(a[x][ARP].hwsrc) + "    ")
                    list.append("IP address of router: " + str(a[x][ARP].psrc) + "    ")

            except Exception as e:
                print("")

            # Checking for SNMP manager and its details
            if raw_packet.find("SNMP") > 0:
                prot = str(a[x][UDP].dport)
                if prot == "161":
                    list.append("SNMP Manager details " + str(a[x][IP].src) + str(a[x][IP].dst) + "    ")

            # List displays in an array format. Hence we join to remove unrequired characters
            modifylist = ''.join(list)
            list1.append(modifylist + "\n\n")
            print(modifylist)
            f1.write(modifylist)
            f1.write("\n")
            f1.write("\n")

        # Login to idenitfy if there are Cisco Network Switch in the pcap file

        raw_packet = str(a[x].command())
        if raw_packet.count("Cisco") > 0:
            v = str(a[x][Raw].command())
            s = str(a[x][Raw].command())
            # print(raw_packet)
            # All the packet information will be stored in the list
            list = []

            list.append("| PACKET " + str(x + 1) + " |   ")
            n = v.find("Cisco")
            data = v[n:]
            list.append(data + "    ")
            if s.count("Switch") > 0:
                list.append("   The device is a SWITCH   ")
            list.append("MAC address of Device: " + str(a[x][Dot3].src)  + "    ")

            # List displays in an array format. Hence we join to remove unrequired characters
            modifylist = ''.join(list)
            list1.append(modifylist + "\n\n")
            print(modifylist)
            f1.write(modifylist)
            f1.write("\n")
            f1.write("\n")
        #Move to next packet
        x += 1
    return num_packets
    f1.close()

if __name__ == '__main__':
    list1 = []
    total_packets =analyzepcap()
    #print(list1)
    storelist = ''.join(list1)

    # root = Tk()
    #
    # # create a Frame for the Text and Scrollbar
    # txt_frm = Frame(root, width=600, height=600)
    # txt_frm.pack(fill="both", expand=True)
    # # ensure a consistent GUI size
    # txt_frm.grid_propagate(False)
    # # implement stretchability
    # txt_frm.grid_rowconfigure(0, weight=1)
    # txt_frm.grid_columnconfigure(0, weight=1)
    #
    # # create a Text widget
    # txt = Text(txt_frm, borderwidth=3, relief="sunken")
    # txt.config(font=("consolas", 12), wrap='word')
    #
    # txt.insert(END, storelist)
    # txt.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
    #
    # # create a Scrollbar and associate it with txt
    # scrollb = Scrollbar(txt_frm)
    # scrollb.grid(row=0, column=1, sticky='nsew')
    # txt['yscrollcommand'] = scrollb.set
    #
    # root.mainloop()

    root = Tk()

    # text1 = Text(root, height=20, width=30)
    # photo=PhotoImage(file='./William_Shakespeare.gif')
    # text1.insert(END,'\n')
    # text1.image_create(END, image=photo)
    #
    # text1.pack(side=LEFT)

    text2 = Text(root,width=165, height=90)
    scroll = Scrollbar(root, command=text2.yview)
    text2.configure(yscrollcommand=scroll.set)
    text2.tag_configure('bold_italics', font=('Arial', 12, 'bold'))
    text2.tag_configure('big', font=('Verdana', 20, 'bold'))
    text2.tag_configure('color', foreground='#476042', font=('Tempus Sans ITC', 12, 'bold'))
    # text2.tag_bind('follow', '<1>', lambda e, t=text2: t.insert(END, "Not now, maybe later!"))
    text2.insert(END,'\nPCAP Packet Content\n', 'big')
    quote = storelist
    text2.insert(END, quote, 'bold_italics')
    # text2.insert(END, 'follow-up\n', 'follow')
    text2.pack(side=LEFT, expand=True)
    scroll.pack(side=RIGHT, fill=Y)

    root.mainloop()
