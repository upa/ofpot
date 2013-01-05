
"""
    OpenFlow Honey Pot Application
"""

from pox.core import *
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of

import re
import thread
import socket

log = core.getLogger ()
fdb = {}
arptable = {}

fdb_mutex = thread.allocate_lock ()
aca_mutex = thread.allocate_lock ()
arp_mutex = thread.allocate_lock ()

FDB_LIFETIME = 60 # sec
OFENTRY_IDLE_TIMEOUT = 10
OFENTRY_HARD_TIMEOUT = 20


CONTROL_PORT = 60003

POT_PORT   = 3
POT_MAC    = "52:54:00:f8:3c:80"
ROUTERMAC  = "00:22:19:c7:a3:35"
VIRTMAC    = "00:00:00:ff:ff:ff"
OWN_PREFIX = "153.16.68.128/26"

def launch () :

    log.info ("OFPOT is Launched")
    core.openflow.addListenerByName ("PacketIn", callback_packet_in)
    core.openflow.addListenerByName ("ConnectionUp", callback_new_dpid)
    core.openflow.addListenerByName ("ConnectionDown", callback_del_dpid)

    # start control thread
    thread.start_new_thread (control_thread, ())
    

def callback_timer () :

    def aging_fdb () :
        delmaclist = []
        for mac in fdb :
            fdb[mac]["timer"] -= 1
            if fdb[mac]["timer"] < 0 :
                delmaclist.append (mac)

        for delmac in delmaclist :
            log.info ("Delete FDB Entry %s" % mac)
            del (fdb[mac])

    def aging_arptable () :
        delmaclist = []
        for mac in arptable :
            arptable[mac]["timer"] -= 1
            if arptable[mac]["timer"] < 0 :
                delmaclist.append (mac)

        for delmac in delmaclist :
            log.info ("Delete ARP Table Entry %s" % mac)
            del (arptable[mac])


    with fdb_mutex :
        aging_fdb ()
    with arp_mutex :
        aging_arptable ()



Timer (1, callback_timer, recurring = True)



def callback_new_dpid (event) :
    log.info ("New OpenFlow Switch is connected [%s]" 
              % dpidToStr (event.dpid))

def callback_del_dpid (event) :
    log.info ("OpenFlow Switch [%s] is disconnected" 
              % dpidToStr (event.dpid))

def callback_packet_in (event) :

    packet = event.parse ()
    log.info ("Packet in : port=%d, src mac=%s, dst mac=%s" %
              (event.port, packet.src, packet.dst))


    # Arp Spoofing for Default Route
    if packet.type == pkt.ethernet.ARP_TYPE :
        arp_packet = packet.payload

        if of.EthAddr (ROUTERMAC) == arp_packet.hwsrc and \
                arp_packet.opcode == pkt.arp.REQUEST :
            send_instead_arp_reply (event, VIRTMAC, arp_packet)
            return

    # Arp snooping
    if packet.type == pkt.ethernet.ARP_TYPE :
        arp_packet = packet.payload

        # Detect existing IP address
        with arp_mutex :
            arptable[str (arp_packet.protosrc)] = \
                {"timer" : FDB_LIFETIME, 
                 "mac"  : arp_packet.hwsrc}
        

    # Aging Arp Table 
    if packet.type == pkt.ethernet.IP_TYPE :
        ip_packet = packet.payload
        with arp_mutex :
            if packet.src != of.EthAddr (POT_MAC) :
                stripsrc = str (ip_packet.srcip)
                if netlookup (stripsrc, OWN_PREFIX) :
                    arptable[stripsrc] = {"timer" : FDB_LIFETIME, 
                                          "mac"  : packet.src}

    # if dst mac is Virtual Mac, change mac, and output correct port
    if packet.dst == of.EthAddr (VIRTMAC) and \
            packet.type == pkt.ethernet.IP_TYPE :
        ip_packet = packet.payload 
        stripdst = str (ip_packet.dstip)

        # Dst IP address exists on arptable
        if arptable.has_key (stripdst) :
            correct_dstmac = arptable[stripdst]["mac"]
            if fdb.has_key (correct_dstmac) :
                correct_dstport = fdb[correct_dstmac]["port"]
            else :
                correct_dstport = of.OFPP_FLOOD

        # Dst IP address does no exist on arptable
        else :
            correct_dstmac = of.EthAddr (POT_MAC)
            correct_dstport = POT_PORT

        flow_mod_change_mac (event, packet,
                             correct_dstport, correct_dstmac)
            
        return


    # Learning Incomming Port
    with fdb_mutex :
        fdb[packet.src] = {"port" : event.port, "timer" : FDB_LIFETIME}

    with fdb_mutex :
        if packet.dst in fdb :
            # if dst mac exists on FDB, send port, and install flow entry
            port = fdb[packet.dst]["port"]
            flow_mod_l2_learning (event, packet, port)
        else :
            # if dst mac DOES NOT exists on FDB, flooding
            packet_out (event, of.OFPP_FLOOD)


def send_instead_arp_reply (event, strmacaddr, arp_packet) :
    
    arp_reply = pkt.arp ()
    arp_reply.hwsrc = of.EthAddr (strmacaddr)
    arp_reply.hwdst = arp_packet.hwsrc
    arp_reply.opcode = pkt.arp.REPLY
    arp_reply.protosrc = arp_packet.protodst
    arp_reply.protodst = arp_packet.protosrc
    ether = pkt.ethernet ()
    ether.type = pkt.ethernet.ARP_TYPE
    ether.src = of.EthAddr (strmacaddr)
    ether.dst = arp_packet.hwsrc
    ether.payload = arp_reply

    msg = of.ofp_packet_out ()
    msg.actions.append (of.ofp_action_output (port = event.port))
    msg.data = ether
    event.connection.send (msg)


def flow_mod_l2_learning (event, packet, port) :

    msg = of.ofp_flow_mod ()
    msg.idel_timeout = OFENTRY_IDLE_TIMEOUT
    msg.hard_timeout = OFENTRY_HARD_TIMEOUT
    msg.match.dl_dst = packet.dst
    msg.actions.append (of.ofp_action_output (port = port))
    msg.buffer_id = event.ofp.buffer_id
    event.connection.send (msg)

    log.info ("Install Flow, dstmac=%s, outport=%d" % (packet.dst, port))


def flow_mod_change_mac (event, packet, port, strdstmac) :

    msg = of.ofp_flow_mod ()
    msg.idel_timeout = OFENTRY_IDLE_TIMEOUT
    msg.hard_timeout = OFENTRY_HARD_TIMEOUT
    msg.match = of.ofp_match.from_packet (packet)
    msg.actions.append (of.ofp_action_dl_addr.set_dst (of.EthAddr (strdstmac)))
    msg.actions.append (of.ofp_action_output (port = port))
    msg.buffer_id = event.ofp.buffer_id
    event.connection.send (msg)

    ip_packet = packet.payload

    log.info ("Install Mac Change Flow, DstIP=%s, SrcIP=%s outport=%d" 
              % (ip_packet.dstip, ip_packet.srcip, port))


def packet_out (event, port) :

    log.info ("Command Packet Out, output port=%d" % port)

    msg = of.ofp_packet_out ()
    msg.actions.append (of.ofp_action_output (port = port))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    event.connection.send (msg)


def netlookup (address, network_with_mask) :
    """
    address is IPv4 Address, network is IPv4 Network Address
    """
    def numto8bit (number) :
        bitstring = ""
        while number :
            bit = number % 2
            number = (number - bit) / 2
            tmp = "%d%s" % (bit, bitstring)
            bitstring = tmp
        for x in range (8 - len (bitstring)) :
            bitstring = "0" + bitstring

        return bitstring

    network, mask = network_with_mask.split ("/")
    
    addressbitstring = ""
    for numstring in address.split (".") :
        addressbitstring += numto8bit (int (numstring))
        
    networkbitstring = ""
    for numstring in network.split (".") :
        networkbitstring += numto8bit (int (numstring))

    if addressbitstring[0:int(mask)] == networkbitstring[0:int(mask)] :
        return True

    return False


def control_thread () :
    
    control_functions = {
        "show-information" : show_information,
        "show-fdb-table" : show_fdb_table,
        "show-arp-table" : show_arp_table,
        "set-honeypot-port" : set_honeypot_port,
        "set-honeypot-mac" : set_honeypot_mac,
        "set-own-prefix" : set_own_prefix,
        "set-virtual-mac" : set_virtual_mac,
        "set-router-mac" : set_router_mac,
        }

    sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind (("127.0.0.1", CONTROL_PORT))

    sock.listen (1)

    while True :
        a_sock, client_address = sock.accept ()

        recvmsg = a_sock.recv (1024)
        recvmsg = recvmsg.strip ()
        recvmsgtuple = recvmsg.split (" ")
        log.info ("Control Command \"%s\"" % recvmsg)

        if recvmsgtuple[0] in control_functions :
            control_functions[recvmsgtuple[0]] (a_sock, recvmsg)
        else :
            a_sock.send ("invalid command\n")

        a_sock.close ()


def show_fdb_table (sock, recvmsg) :

    with fdb_mutex :
        maclist = fdb.keys ()

        maclist.sort ()
        sock.send ("MAC Address\t\tPort\tLifetime\n")
        for mac in maclist :
            sock.send ("%s\t%d\t%d\n" 
                       % (mac, fdb[mac]["port"], fdb[mac]["timer"]))

def show_arp_table (sock, recvmsg) :

    with arp_mutex :
        addrlist = arptable.keys ()

        addrlist.sort ()
        sock.send ("IP Address\tMAC Address\tLifetime\n")
        for addr in addrlist :
            sock.send ("%s\t%s\t%d\n"
                       % (addr, arptable[addr]["mac"], 
                          arptable[addr]["timer"]))

def show_information (sock, recvmsg) :

    sock.send ("Own Prefix           : %s\n" % OWN_PREFIX)
    sock.send ("Honeypot Port        : %d\n" % POT_PORT)
    sock.send ("Honeypot Mac Address : %s\n" % POT_MAC)
    sock.send ("Virtual Mac Address  : %s\n" % VIRTMAC)
    sock.send ("Router Mac Address   : %s\n" % ROUTERMAC)


def set_honeypot_port (sock, recvmsg) :
    
    try :
        command, port = recvmsg.split (" ")
    except :
        sock.send ("invalid command \"%s\"\n" % recvmsg)
        return
    
    try :
        potport = int (port)
    except :
        sock.send ("invalid port number \"%s\"\n" % port)
        return
    
    log.info ("Change Honeypot Port %d" % potport)

    global POT_PORT
    POT_PORT = potport


def set_honeypot_mac (sock, recvmsg) :
    
    try :
        command, mac = recvmsg.split (" ")
    except :
        sock.send ("invalid command \"%s\"" % recvmsg)
        return
    
    if not re.match (r'([0-9A-Fa-f]{2,2}:){5,5}[0-9A-Fa-f]{2,2}', mac) :
        sock.send ("invalid mac address \"%s\". [XX:XX:XX:XX:XX:XX]\n" % mac)
        return

    log.info ("Change Honeypot Mac Address %s" % mac)

    global POT_MAC
    POT_MAC = mac


def set_own_prefix (sock, recvmsg) :
    
    try :
        command, prefix = recvmsg.split (" ")
    except :
        sock.send ("invalid command \"%s\"" % recvmsg)
        return
    
    if not re.match (r'([0-9]{1,3}\.){3,3}[0-9]{1,3}/[0-9]{1,2}', prefix) :
        sock.send ("invalid prefix \"%s\".\n" % prefix)
        return

    log.info ("Change Honeypot Own Prefix %s" % prefix)

    global OWN_PREFIX
    OWN_PREFIX = prefix


def set_virtual_mac (sock, recvmsg) :
    
    try :
        command, mac = recvmsg.split (" ")
    except :
        sock.send ("invalid command \"%s\"" % recvmsg)
        return
    
    if not re.match (r'([0-9A-Fa-f]{2,2}:){5,5}[0-9A-Fa-f]{2,2}', mac) :
        sock.send ("invalid mac address \"%s\". [XX:XX:XX:XX:XX:XX]\n" % mac)
        return

    log.info ("Change Virtual Mac Address %s" % mac)

    global VIRTMAC
    VIRTMAC = mac


def set_router_mac (sock, recvmsg) :
    
    try :
        command, mac = recvmsg.split (" ")
    except :
        sock.send ("invalid command \"%s\"" % recvmsg)
        return
    
    if not re.match (r'([0-9A-Fa-f]{2,2}:){5,5}[0-9A-Fa-f]{2,2}', mac) :
        sock.send ("invalid mac address \"%s\". [XX:XX:XX:XX:XX:XX]\n" % mac)
        return

    log.info ("Change Router Mac Address %s" % mac)

    global ROUTERMAC
    ROUTERMAC = mac
