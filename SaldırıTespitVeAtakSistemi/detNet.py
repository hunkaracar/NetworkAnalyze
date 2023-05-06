#!/usr/bin/python3

import scapy.all as scapy
from scapy.all import *
from scapy.all import ARP,Ether
import modul1
import nmap
import argparse
import logging
import pprint
import time


logging.getLogger("scapy").setLevel(logging.ERROR)




def get_documentation():
    print("""
####################################################################
#                                                                  #
# _______ _______ _______ _______ _______ _______ _______          #
# |\     /|\     /|\     /|\     /|\     /|\     /|\     /|        #
# | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |        #
# | |   | | |   | | |   | | |   | | |   | | |   | | |   | |        #
# | |d  | | |e  | | |t  | | |N  | | |e  | | |t  | | |s  | |        #
# | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |        #
# |/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|        #
#                                                                  #
# program name:Detection Network        development:@hunkaracar    #
# Check Your Networks :)                github:hunkaracr1          #
#                                                                  #
#                                                                  #
####################################################################
    """)
    print("detNet 2.7.9")
    print("---------------------------------------------------------------------------\n")
    
    
    parser = argparse.ArgumentParser(
        prog='detNet',
        description='Detection Network'
    )

    parser.add_argument('-ip', '--ipaddress', type=str,
                        help='You must enter the Ip address (REQUIRED)')
    parser.add_argument('-f', '--filter', type=str,
                        help='enter which packet or ip address you will filter')
    parser.add_argument('-i','--iface',type=str,
    		        help='specify the interface you use for packet analysis')
    parser.add_argument('-ids','--ids',
                        help='detects malicious network activity')
    parser.add_argument('-Se', '--service', help='detects standing devices')
    parser.add_argument('-P', '--port', help='port scan')
    parser.add_argument('-P-', '--ports', help='ALL the port scan')
    parser.add_argument('-Op', '--operatingsystem',
                        help='makes operating system discovery of standing devices')
    parser.add_argument('-Sv', '--version',
                        help='Retrieves version information of running services of standing devices')
    parser.add_argument('-inf','--ninformation',type=str,
                        help='Shows basic router and mac address information on local network')
  

    args = parser.parse_args()

    return args
    
    


import scapy.all as scapy

def get_ip_mac(ip):

    # arp request is sent and host and mac discovery is done(CIDR notation)
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combines packages
    arp_request_broadcast = arp_broadcast/arp_request

    #print(ip + " ...")
    answered_list = scapy.srp(arp_request_broadcast, timeout=30, verbose=True)[0]

    if answered_list:
        print("Host and Mac information of devices on the network\n")
        
        return answered_list.summary()
        
    else:
        print("No device found with the given IP address range")
     
     


def get_filter(iface,packet_filter):
     
     try:
    	 print("\nFiltered packet is Showing...")
    	 print("----------------------------------------------")
    	 time.sleep(2)
    	
    	 #listen for packets on the specified network interface but by filtered packet
    	 sniff_packet_filtered = sniff(filter=packet_filter,iface=iface,prn=lambda packet_fltr : packet_fltr.summary())
    	
    	 return sniff_packet_filtered
    	
     except KeyboardInterrupt:
            print("The program has been stopped!")
            time.sleep(1)
            
     finally:
	     with open('packetanalyzeFiltered.txt','wb') as file:
	          for packetfltr in sniff_packet_filtered:
	              file_result = file.write(repr(packetfltr).encode() + b"\n") #repr() function convert to with encode() and is writable
	         
    


def packet_analyze(iface):
    
    try:
    	print("\nPackets is Showing...")
    	print("--------------------------------------------")
    	time.sleep(2)
    	
    	#listen for packets on the specified network interface
    	sniff_packet = sniff(iface=iface, prn=lambda packet: packet.summary()) 
    	
    	return sniff_packet
    
    except KeyboardInterrupt:
    	   print("The program has been stopped!")
    	   time.sleep(1)
    	   
    finally:
           with open ('packetanalyze.txt','wb') as file:
                for packet in sniff_packet:
                    file.write(repr(packet).encode() + b"\n")  #repr() function convert to with encode() and is writable
                 
                    


def gets_ids(iface, packet):

    packet = sniff(iface=iface, prn=lambda packet: packet.summary())

    try:
        # ARP packet fetch
        if packet.haslayer(ARP):
            src_ip = packet[IP].psrc
            dst_ip = packet[IP].pdst
            arp_type = packet[ARP].op
            
            if arp_type >= 12:
                print(f"abnormal arp packet detected. Source IP: {src_ip}, Target IP: {dst_ip}, Type: {arp_type}")

        # ICMP packet fetch
        elif packet.haslayer(ICMP):
            src_ip = packet[ICMP].src
            dst_ip = packet[ICMP].dst
            icmp_type = packet[ICMP].type
            
            if icmp_type >= 10:
                print(f"ICMP ping detected. Source IP: {src_ip}, Target IP: {dst_ip}, Type: {icmp_type}")

        # SYN FLOOD fetch
        elif packet.haslayer(TCP) and packet[TCP].flags == 0x02:
            src_ip = packet[TCP].src
            dst_ip = packet[TCP].dst
            tcp_sport = packet[TCP].sport
            
            print(f"SYN flood detected. Source IP: {src_ip}, Target IP: {dst_ip}, Source Port: {tcp_sport}")

        # UDP FLOOD fetch     
        elif packet.haslayer(UDP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            udp_dport = packet[UDP].dport
            
            if udp_dport >= 100:
                print(f"DNS amplification attack detected. Source IP: {src_ip}, Target IP:{dst_ip}, Destination Port:{udp_dport}")

        # DEAUTH packet fetch
        elif packet.haslayer(Dot11Deauth):
            src_mac = packet.addr2
            dst_mac = packet.addr1
            
            print(f"DEAUTH attack detected. Source MAC: {src_mac}, Destination MAC: {dst_mac}")

        else:
            print("No-Packet")


    except Exception as e:
        print(f"Exception: {e}")
    
   

    # Return None, as there is no clear use for this variable in the code
    return "Program Terminated.."
    time.sleep(2)

    #Capture network packets using the gets_ids() function as the callback
    #network_result = sniff(filter="arp or icmp or tcp or udp or wlan", prn=gets_ids, iface=iface)
    
    network_result = sniff(iface=iface, prn=lambda packet: packet.summary())
    
    return network_result
        
             


def get_port(ip, port):

    scanner = nmap.PortScanner()
    scan_result = scanner.scan(hosts=ip, arguments=f'-v -sS -p {port}')
    #print(type(scan_result)) => dict

    for line in scan_result:
        print("\n", line)
        print("**********\n")
        for item, key in scan_result[line].items():
            print(f"{item}:{key}")
    print("\n")
    
    
    
    
    

def get_service(ip):
    scanner = nmap.PortScanner()
    scan_result = scanner.scan(hosts=ip, arguments='-v -sP')

    for host in scan_result['scan']:
        print("host : %s (%s)" % (host, scan_result['scan'][host]['hostnames'][0]['name']))
        print("state: %s" % scan_result['scan'][host]['status']['state'])






def get_operating_Sys(ipv4):
    
    scanner = nmap.PortScanner()
    scan_result = scanner.scan(hosts=ipv4, arguments='-v -O -A -T4')
    
    #print(type(scan_result)) => dict type 
    
    for host,host_data in scan_result.items():
        print(f"Results for host {host}:")
        
        if "osmatch" in host_data:
            for osmatch in host_data["osmatch"]:
                print(f"Detected OS: {osmatch['name']} ({osmatch['accuarcy']}% accuracy)")
                
        else:
            print("No operating system detected!!")
            
            
            

def get_version(ipv42):
    
    scanner = nmap.PortScanner()
    scan_result = scanner.scan(hosts=ipv42, arguments='-v -sV -T4')
    
    #print(type(scan_result)) => dict type
    
    hosts = {}
    for host,host_data in scan_result['scan'].items():
        host_info = {}
        
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                if 'product' in port_data and 'version' in port_data:
                    host_info[str(port)] = {
                    'product' : port_data['product'],
                    'version' : port_data['version']
                    }
                    
        hosts[host] = host_info
    
    return hosts
        
    
    

def get_ports(ip):

    scanner = nmap.PortScanner()
    host = ip
    argumet = "-v -sS -p 1-20000 -T4"
    scan_result = scanner.scan(hosts=host, arguments=argumet)
    
    #print(type(scan_result)) => dict type
    
    #logic process
    if scan_result:
       
       #access the dict values 
       for host in scan_result['scan']:
           print("scanning...")
           print("---------------------------------")
           time.sleep(2)
           print('host : %s (%s)' % (host, scan_result['scan'][host]['status']['state']))
           for port in scan_result['scan'][host]['tcp']:
               print("port: %s\tstate: %s\t services: %s" % (port, scan_result['scan'][host]['tcp'][port]['state'], scan_result['scan'][host]['tcp'][port]['name'] ))
            	
    else:
         print("open port not found..")
         
         
def general_network_information(iface,give_ip):
    
    #get_list_interfaces()
    #general_information_conf()
    #use_router_display()
    #get_routerIp_address()
    #local_mac_oninterface(us_iface)
    #get_mac_by_ip(give_ip)
    
    
    modul1.get_list_interfaces()
    print("========================================================")
    print(modul1.general_information_conf())
    print("========================================================")
    print(modul1.use_router_display())
    print("========================================================")
    print(modul1.get_routerIp_address())
    print("========================================================")
    print("Shows mac address on local Network interface => {0}".format(modul1.local_mac_oninterface(iface)))
    print("========================================================")
    print("Mac address of target device ip addres => {0} ".format(modul1.get_mac_by_ip(give_ip)))
    
    
    
        
    

def generate_outfile():
    pass

         
          
    
    
def main():

    args = get_documentation()
    
    ip = args.ipaddress
    ports = args.ports
    ipv = args.service
    ipv4 = args.operatingsystem
    ipv42 = args.version
    i_face = args.iface
    filter_r = args.filter
    ids = args.ids
    give_ip = args.ninformation
    
    

    if args.filter:
       print(get_filter(i_face, filter_r))
    
    
    elif args.ids:
         print(gets_ids(i_face, ids))
         
         
    elif args.ninformation:
         print(general_network_information(i_face, give_ip))
         
         
    else:
         if args.iface:
            print(packet_analyze(i_face))
            
         if args.ipaddress:
            print(get_ip_mac(ip))
            
         if args.port:
            pprint.pprint(get_port(ip, port))
            
         if args.ports:
            print(get_ports(ports))
            
         if args.service:
            print(get_service(ipv))
            
         if args.operatingsystem:
            print(get_operating_Sys(ipv4))
            
         if args.version:
            pprint.pprint(get_version(ipv42))
    
    
 
    
if __name__ == "__main__":
    
    main()

