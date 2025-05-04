#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class ForwardTableItem:
    def __init__(self, pref, mas, nex, inter):
        self.prefix = pref
        self.mask = mas
        self.nexthop = nex
        self.interfacename = inter


class QueueItem:
    def __init__(self, pkt, subnet, port, targetIP):
        self.packet = pkt
        self.currentTime = time.time()
        self.retryTime = 0
        self.matchSubnet = subnet
        self.sendingPort = port
        self.targetIPAddr = targetIP


class TargetIPQueue:
    def __init__(self, targetip, currentTime):
        self.targetip = targetip
        self.currentTime = currentTime
        self.retryTime = 0
        self.targetiplist = []


class Router:
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.interfaces = net.interfaces()
        self.arp_table = {}            # key: IP, value: MAC
        self.forwarding_table = []
        self.myqueue = []

        # Step 1: Initialize forwarding table with interfaces
        for i in self.interfaces:
            temp_prefix = IPv4Address(int(i.ipaddr) & int(i.netmask))
            temp_mask = IPv4Address(i.netmask)
            self.forwarding_table.append(
                ForwardTableItem(temp_prefix, temp_mask, '0.0.0.0', i.name)
            )

        # Step 2: Load static routes from file
        with open("forwarding_table.txt") as file:
            for line in file:
                data = line.strip()
                if data:
                    sp = data.split(" ")
                    self.forwarding_table.append(
                        ForwardTableItem(
                            IPv4Address(sp[0]),
                            IPv4Address(sp[1]),
                            IPv4Address(sp[2]),
                            sp[3]
                        )
                    )

        log_info("---------------FORWARDING TABLE----------------")
        for a in self.forwarding_table:
            log_info(f"{a.prefix} , {a.mask} , {a.nexthop} , {a.interfacename}")
        log_info("-----------------------------------------------")

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        eth = packet.get_header(Ethernet)
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)

        if 'Vlan' in packet.headers():
            return

        log_info("-------------------ARP TABLE-------------------")
        for myip, mymac in self.arp_table.items():
            log_info(f"    IP: {myip};     MAC: {mymac}")
        log_info("-----------------------------------------------")

        # Step 1: Ethernet filtering
        port = self.net.interface_by_name(ifaceName)
        check = False

        if eth:
            if eth.dst != 'ff:ff:ff:ff:ff:ff':
                if port.ethaddr == eth.dst:
                    check = True
                    log_info("pass eth packet at step 1")
            else:
                check = True
                log_info(f"eth.dst should be broadcast: {eth.dst}")
            if not check:
                log_info("Drop an irrelevant packet at step 1")
                return

        # Step 2: Handle ARP packets
        if arp:
            check2 = False
            for intf in self.interfaces:
                if intf.ipaddr == arp.targetprotoaddr:
                    check2 = True
                    intfs = intf
                    log_info("pass arp packet at step 2")
                    break

            if not check2:
                log_info("Drop an irrelevant packet at step 2")
                return

            self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr

            if arp.operation == ArpOperation.Request:
                log_info("arp request")
                reply = create_ip_arp_reply(
                    intfs.ethaddr, arp.senderhwaddr,
                    arp.targetprotoaddr, arp.senderprotoaddr
                )
                self.net.send_packet(ifaceName, reply)

            elif arp.operation == ArpOperation.Reply:
                if arp.senderhwaddr != 'ff:ff:ff:ff:ff:ff':
                    self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
                    log_info("arp reply success!")
                else:
                    log_info("arp reply fail, broadcast!")

        # Step 3: Handle IPv4 packets
        elif ipv4:
            if not check:
                return

            ipv4.ttl -= 1
            dropOrNot = False
            maxPrefixLen = 0

            for addr in self.interfaces:
                if ipv4.dst == addr.ipaddr:
                    dropOrNot = True
                    log_info("a packet for router itself")

            if not dropOrNot:
                for i in self.forwarding_table:
                    if (int(ipv4.dst) & int(i.mask)) == int(i.prefix):
                        networkAddr = IPv4Network(f"{i.prefix}/{i.mask}")
                        if networkAddr.prefixlen > maxPrefixLen:
                            maxPrefixLen = networkAddr.prefixlen
                            match_subnet = i.prefix
                            match_next_hop = i.nexthop
                            match_interface = i.interfacename

                if maxPrefixLen == 0:
                    log_info("forwarding_table cannot match")
                    return

                match_destip = ipv4.dst if match_next_hop == '0.0.0.0' else IPv4Address(match_next_hop)
                log_info("enter enque")
                new_packet = QueueItem(packet, match_subnet, match_interface, match_destip)

                for a in self.myqueue:
                    if a.targetip == match_destip:
                        a.targetiplist.append(new_packet)
                        break
                else:
                    new_queue = TargetIPQueue(match_destip, time.time())
                    new_queue.targetiplist.append(new_packet)
                    self.myqueue.append(new_queue)

    def forwarding(self):
        delete = []

        for queue in self.myqueue:
            targetIPAddr = queue.targetip

            if targetIPAddr in self.arp_table:
                for queued_item in queue.targetiplist:
                    senderPort = queued_item.sendingPort
                    routerPort = self.net.interface_by_name(senderPort)
                    mypacket = queued_item.packet
                    mypacket[Ethernet].src = routerPort.ethaddr
                    mypacket[Ethernet].dst = self.arp_table[targetIPAddr]
                    self.net.send_packet(senderPort, mypacket)
                    log_info("send a packet")

                delete.append(queue)
                log_info("delete a full ip at empty list")

            elif queue.retryTime < 5:
                senderPort = queue.targetiplist[0].sendingPort
                routerPort = self.net.interface_by_name(senderPort)

                if queue.retryTime == 0 or time.time() - queue.currentTime > 1.0:
                    ether = Ethernet(
                        src=routerPort.ethaddr,
                        dst='ff:ff:ff:ff:ff:ff',
                        ethertype=EtherType.ARP
                    )
                    arp = Arp(
                        operation=ArpOperation.Request,
                        senderhwaddr=routerPort.ethaddr,
                        senderprotoaddr=routerPort.ipaddr,
                        targethwaddr='ff:ff:ff:ff:ff:ff',
                        targetprotoaddr=targetIPAddr
                    )
                    self.net.send_packet(senderPort, ether + arp)
                    queue.retryTime += 1
                    queue.currentTime = time.time()

            elif queue.retryTime >= 5:
                if time.time() - queue.currentTime > 1.0:
                    delete.append(queue)
                    log_info("delete a full ip at try > 5")

        for k in delete:
            self.myqueue.remove(k)

    def start(self):
        '''Main loop: receive packets and forward'''
        while True:
            self.forwarding()
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''Entry point'''
    router = Router(net)
    router.start()
