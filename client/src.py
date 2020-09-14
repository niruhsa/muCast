#!/usr/bin/python3
import socket, time, ipaddress, netifaces, argparse

class MulticastAnnouncerClient:

    def __init__(self, **kwargs):
        self.MCAST_GROUP = '224.1.1.1'
        self.MCAST_PORT = 4180
        self.MCAST_TTL = 3
        self.blacklisted_interfaces = [ 'lo', 'lo0' ]
        self.name = kwargs['nickname']
        self.ipv6 = kwargs['ipv6']
        self.timer = kwargs['timer']
        self.ips = {}
        self.last_transmitted = None

        if self.name is None or len(self.name) == 0: raise Error("The name that you entered cannot be empty")

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
                        except: pass
    
    def sendPacket(self, address):
        self.last_transmitted = time.time()
        data = "{}:{}".format(self.name, address)
        self.sock.sendto(bytes(data, "utf-8"), (self.MCAST_GROUP, self.MCAST_PORT))

if __name__ == "__main__":
    def str2bool(v):
        if isinstance(v, bool): return v
        if v.lower() in ('yes', 'true', 't', 'y', '1'): return True
        elif v.lower() in ('no', 'false', 'f', 'n', '0'): return False
        else: raise argparse.ArgumentTypeError('Boolean value expected.')

    parser = argparse.ArgumentParser(description="Multicast IP Announcer")
    parser.add_argument('nickname', type=str)
    parser.add_argument('-ipv6', type=str2bool, nargs='?', const=True, default=False, help='Enable IPv6 IP Reporting')
    parser.add_argument('-timer', type=int, nargs='?', const=True, default=30, help='How long it should wait before rebroadcasting all IPs if no changes are detected in seconds')
    args = vars(parser.parse_args())
    MCAClient = MulticastAnnouncerClient(**args)


