#!/usr/bin/python3

from scapy.all import *


def get_list_interfaces():
    
    list_interfaces = get_if_list()
    #print(type(list_interfaces)) => list type
    print("Interfaces used:")
    for iface in list_interfaces:
        print("iface=>",iface)
        
    #return iface
    
    
def general_information_conf():
    
    #Shows general interface information
    return conf.ifaces
    
    
    
def use_router_display():
    
    #You can use it to display the routers or get specific routing
    return conf.route
    
    
def get_routerIp_address():
    
    #get router ip address
    router_ip = conf.route.route("0.0.0.0")     #print(type(router_ip)) => tuple type
    
    return "\nrouter ip => " + router_ip[2]


def local_mac_oninterface(us_iface):
    
    #get local mac / mac of an interface
    mac = get_if_hwaddr(us_iface)
    
    return mac
    
def get_mac_by_ip(give_ip):
    
    #get mac by ip => exam 10.0.0.7
    mac = getmacbyip(give_ip)
    
    return mac 
    
    
    
       

#get_list_interfaces()
#general_information_conf()
#print(get_routerIp_address())
#print(local_mac_oninterface("eth0"))
#print(get_mac_by_ip("10.0.2.10"))












