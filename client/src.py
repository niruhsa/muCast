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
        self.last_transmitted = 0

        if self.name is None or len(self.name) == 0: raise Error("The name that you entered cannot be empty")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.MCAST_TTL)

        self.listenForChanges()

    def listenForChanges(self):
        while True:
            try:
                old_ips = self.ips.copy()
                self.getIPs()
                for interface in self.ips.keys():
                    for ip in self.ips[interface]:
                        if interface not in old_ips.keys(): self.sendPacket(ip['addr'])
                        else:
                            match = False
                            for oip in old_ips[interface]:
                                if oip['addr'] == ip['addr']: match = True
                            if not match: self.sendPacket(ip['addr'])

                if time.time() - self.last_transmitted > int(self.timer):
                    for interface in self.ips:
                        for ip in self.ips[interface]:
                            print(ip)

            except Exception as e: print(e)
            time.sleep(1)

    def getIPs(self):
        for inter in netifaces.interfaces():
            if inter not in self.blacklisted_interfaces:
                interface = netifaces.ifaddresses(inter)
                for address in interface:
                    if inter not in self.ips: self.ips[inter] = interface[address]
                    else: self.ips[inter] += interface[address]

                    l = self.ips[inter].copy()
                    new_l = []
                    for item in l:
                        in_new = False
                        for oitem in new_l:
                            if item['addr'] == oitem['addr']: in_new = True
                        if not in_new: new_l.append(item)
                    self.ips[inter] = new_l
    
    def sendPacket(self, address):
        try:
            id = self.randomString()
            t = time.time()
            data = "{}:{}:{}:{}".format(self.name, address, id, t)
            ip_type = ipaddress.ip_address(address)
            if self.verbose or (self.verbose and isinstance(ip_type, ipaddress.IPv6Address) and self.ipv6):
                print("[VERBOSE] Sending packet {} at {} with content {}".format(id, t, self.name + ":" + address), file=sys.stderr)
            
            if isinstance(ip_type, ipaddress.IPv6Address) and self.ipv6: self.sock.sendto(bytes(data, "utf-8"), (self.MCAST_GROUP, self.MCAST_PORT))
            else: self.sock.sendto(bytes(data, "utf-8"), (self.MCAST_GROUP, self.MCAST_PORT))
            
            self.last_transmitted = t
            return True
        except: return False

            

    def randomString(self, length=8):
        ret = ""
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        for i in range(length): ret += chars[random.randint(0, len(chars) - 1)]
        return ret
