#!/usr/bin/python

""" Maskfind 1.5 11/13/2012

''' I wrote this because I couldn't find anything that could work out a remote subnet mask which is useful
''' during the discovery phase of a penetration test. I noticed that sometimes people were missing some of 
''' the IP addresses on a router/firewall when port scanning a host.

''' You can do what you want with this code """

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import socket
import re
from scapy.all import *
from netaddr import IPAddress

def DisplayUsage():
    print "\nWorks out if a remote host interface has additional IP's in same subnet assigned to it\nRun maskfind against a host before portscanning to ensure you scan everything\n"
    print "This will give accurate results providing ICMP is enabled on the second\nto last hop. Host must be at least two hops away\n\n"
    print "Usage: maskfind.py [-h]elp [-v]erbose [-t]imeout [-m]axTTL destination"
    print "Recommended - maskfind.py -v host.domain.com\n"
    sys.exit(0)

def PrintIfVerbose(string):
    if VerboseFlag == True:
        print string
    return

def GetLastRouterHopCount(HostIp, MaxTTL, Timeout):
    """Function that gets the hop count to the router before the actual host"""
    ttl = 1

    while GetLastRouterIp(HostIp,ttl,True, Timeout) != HostIp:
        if ttl >= MaxTTL:
            print "\nFailed to reach destination host.\n\nEither \na)Maximum TTL has been exceeded (This can be modified with the -m switch)\nb)The destination host has ICMP disabled\nc)The network node before the destination host has ICMP disabled. \n\nIf you would like to troubleshoot this, the first step would be to try and ICMP Traceroute it"
            sys.exit(0) 
        ttl += 1

    return ttl-1

def GetLastRouterIp(HostIp, ttl, DisableVerboseMode, Timeout):	
    """Function that will return the router address at a specified point along the path"""
    ans = sr1(IP(dst=HostIp,ttl=ttl)/ICMP(),verbose=0,timeout=Timeout)
	
    if not ans:
        ans = sr1(IP(dst=HostIp,ttl=ttl)/ICMP(),verbose=0,timeout=Timeout)
		
    if not ans:
        return str(None)

    if DisableVerboseMode == False:
        PrintIfVerbose("IP:" + str(HostIp) + " --> Gateway:" + str(ans.getlayer(IP).src))
    
    return str(ans.getlayer(IP).src)

def main(HostIp, VerboseFlag, MaxTTL, Timeout):
    HostIpTop = HostIp + 1
    HostIpLow = HostIp - 1
    LastRouterHopCount = GetLastRouterHopCount(str(HostIp), MaxTTL, Timeout)
    LastRouterIp = GetLastRouterIp(str(HostIp), LastRouterHopCount, True, Timeout)
    print "\nStarting maskfind... Attempting to locate additional IP addresses on remote router\n"
    print "Target IP is " + str(HostIp) 
    print "Network node before target is  " + LastRouterIp
    print "MaxTTL is " + str(MaxTTL)
    print "Timeout is " + str(Timeout) + " seconds \n"
	
    while(GetLastRouterIp(str(HostIpTop),LastRouterHopCount,False, Timeout) == LastRouterIp):	
        HostIpTop += 1
		
    while(GetLastRouterIp(str(HostIpLow),LastRouterHopCount,False, Timeout) == LastRouterIp):
        HostIpLow -= 1
		
    if HostIpTop -1 == HostIpLow +1:
        print "No additional IP addresses found on remote router:"+ str(HostIp)+ "/32\n"
    else:
        print "\nHighest Address Is = " + str(HostIpTop - 1)
        print "Lowest Address Is = " + str(HostIpLow + 1) +"\n"
        print "Alternatively, aim port scanners at " + str(HostIpLow+1) + " - " + str(HostIpTop-1) + "\n"
    
    sys.exit(0)


if __name__ == "__main__":
    VerboseFlag = False
    MaxTTL = 30
    Timeout = 5
    
    if len(sys.argv) > 1:
        for x in sys.argv:
            if x == "-v":
                VerboseFlag = True
            if x == "-h":
                DisplayUsage()
                sys.exit(0)
            if x == "-m":
                MaxTTL = sys.argv[sys.argv.index(x)+1]
            if x == "-t":
                if int(sys.argv[sys.argv.index(x)+1]) != 0 and int(sys.argv[sys.argv.index(x)+1]) < 11:
                    Timeout = sys.argv[sys.argv.index(x)+1]
                else:
                    print "Timeout must be between 1-10 seconds; adjusting to default (5s)"
            if re.match('^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$', x) or re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', x):
                try:
                    main(IPAddress(socket.gethostbyname(str(x))),VerboseFlag, int(MaxTTL), int(Timeout))
                except socket.gaierror as e:
                    break
                    
        print "Please specify a valid host."
        sys.exit(-1)

    DisplayUsage()
