# PCAP_Analyzer

| REQUIREMENTS |

Python 3.X
Scapy-python-3 module

| MOTIVATION |

Understand how scapy can be used to interpret pcap files.
Explore and experiment different functions in Scapy.
Find out the OS from pcap packet content using different approach as given below.

| HIGH LEVEL APPROACH |

There are some signs to find the OS, but none of them are 100% reliable.

Look for typical values for MSS and Windows size in TCP connections
Look for typical RTT values:	http://www.netresec.com/?page=Blog&month=2011-11&post=Passive-OS-Fingerprinting
Look for typical protocols of a certain OS (netbios, etc.)
Look for sign of certain client software (Browser: User-Agent, Banner, etc.)
Look for the TCP source ports used. There are difference of those ranges between different OSes
Look for the IP ID and how it changes. There are difference of ID between different OSes

| APPROACH FOR OS DETECTION |

Extract GET/POST Request.
Look for User-Agent string in HTTP Headers
In User-Agent - find OS
For malicious packets monitor HTTP Status Code - 302 - Redirection
Analyze hexdump to find signatures related to metasploit etc. For example metasploit = 6D 65 74 61 73 70 6C 6F 69 74
Analyze unique strings in hexdump to find OS, services etc.
Identify other network devices like firewalls, switches, router etc.
Use of gnuplot python library
