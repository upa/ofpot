OFPOT
=====

OpenFlow HoneyPot (ofpot) is an OpenFlow application running on POX 
(http://www.noxrepo.org/pox/about-pox/).
ofpot detects unused IP addresses with arp snooping,
and twists the flow from internet nodes to unused IP addresses to 
specified HoneyPot using destination mac address swap.

	 
	 % git clone git://github.com/noxrepo/pox.git
	 % git clone git://github.com/upa/ofpot.git
	 % cp ofpot/ofpot.py pox/ext/
	 % cd pox
	 % ./pox.py ofpot

	 % cd ofpot
	 % ./ctlofpot 
	    OpenFlow Honeypot Control Command

	     ctlofpot [Command] ([argument])

	     show-information            : print basic information
	     show-fdb-table              : print Forwarding Data Base
	     show-arp-table              : print ARP table
	     set-honeypot-port [PortNum] : set output port to Honeypot
	     set-honeypot-mac  [MacAddr] : set Mac address of Honeypot node
	     set-own-prefix    [Prefix]  : set local IP address prefix
	     set-virtual-mac   [MacAddr] : set Virtual Mac Address
	     set-router-mac    [MacAddr] : set Mac address of Default Router
	 % 
	 

For jissenkobo.
