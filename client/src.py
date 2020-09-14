#!/usr/bin/python3
import socket, time, ipaddress, netifaces, string, random, sys

class MulticastAnnouncerClient:

    def __init__(self, **kwargs):
        self.MCAST_GROUP = '224.1.1.1'
        self.MCAST_PORT = 4180
        self.MCAST_TTL = 3
        self.blacklisted_interfaces = [ 'lo', 'lo0' ]
        self.name = kwargs['nickname']
        self.ipv6 = kwargs['ipv6']
        self.timer = kwargs['timer']
        self.verbose = kwargs['v']
        self.ips = {}
        self.last_transmitted = None

        if self.name is None or len(self.name) == 0: raise Error("The name that you entered cannot be empty")

        sys.stdout.flush()
        sys.stderr.flush()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.MCAST_TTL)
        self.listenForChanges()

    def listenForChanges(self):
        try:
            while True:
                old_ips = self.ips.copy()
                self.getIPs()
                for interface in self.ips.keys():
                    ip = self.ips[interface]
                    if interface not in old_ips.keys(): self.sendPacket(ip)
                    elif old_ips[interface] != ip: self.sendPacket(ip)
                if time.time() - self.last_transmitted > self.timer:
                    for interface in self.ips.keys():
                        ip = self.ips[interface]
                        self.sendPacket(ip)
                time.sleep(1)
        except KeyboardInterrupt: pass

    def getIPs(self):
        for inter in netifaces.interfaces():
            if inter not in self.blacklisted_interfaces:
                interface = netifaces.ifaddresses(inter)
                for address in interface:
                    if len(interface[address][0]['addr']) > 0:
                        try:
                            classType = ipaddress.ip_address(interface[address][0]['addr'])
                            if isinstance(classType, ipaddress.IPv6Address) and self.ipv6: self.ips[inter] = interface[address][0]['addr']
                            else: self.ips[inter] = interface[address][0]['addr']
                        except Exception as e: pass
    
    def sendPacket(self, address):
        id = self.randomString()
        t = time.time()
        if self.verbose: 
            print("[VERBOSE] Sending packet {} at {} with content {}".format(id, t, self.name + ":" + address), file=sys.stderr)
        data = "{}:{}:{}:{}".format(self.name, address, id, t)
        self.sock.sendto(bytes(data, "utf-8"), (self.MCAST_GROUP, self.MCAST_PORT))
        self.last_transmitted = t

    def randomString(self, length=8):
        ret = ""
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        for i in range(length): ret += chars[random.randint(0, len(chars) - 1)]
        return ret
