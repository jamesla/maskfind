# Maskfind

I wrote this because I couldn't find anything that could work out a remote subnet mask which is useful
during the discovery phase of a penetration test. I noticed that sometimes people were missing some of 
the IP addresses on a router/firewall when port scanning a host.

###Example
![Alt text](/maskfind.jpg?raw=true "What maskfind does")

Works out if a remote host interface has additional IP's assigned to it
Run maskfind against a host before portscanning to ensure you scan everything

This will give accurate results providing ICMP is enabled on the second
to last hop. Host must be at least two hops away

###Usage: 
```
maskfind.py [-h]elp [-v]erbose destination
```
