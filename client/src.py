import socket, time, ipaddress, netifaces, argparse

class MulticastAnnouncerClient:

    def __init__(self, **kwargs):
        self.MCAST_GROUP = '224.1.1.1'
        self.MCAST_PORT = 4180
        self.MCAST_TTL = 3
        self.blacklisted_interfaces = [ 'lo', 'lo0' ]
        self.name = kwargs['nickname']
        self.ipv6 = kwargs['ipv6']

        if self.name is None or len(self.name) == 0: raise Error("The name that you entered cannot be empty")
        while True:
            self.send()
            time.sleep(30)

    def send(self):
        for inter in netifaces.interfaces():
            if inter not in self.blacklisted_interfaces:
                interface = netifaces.ifaddresses(inter)
                for address in interface:
                    if len(interface[address][0]['addr']) > 0:
                        addr = interface[address][0]['addr']
                        try:
                            classType = ipaddress.ip_address(addr)
                            if isinstance(classType, ipaddress.IPv6Address) and self.ipv6: self.sendPacket(addr)
                            else: self.sendPacket(addr)
                        except: pass
    
    def sendPacket(self, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.MCAST_TTL)

        data = "{}:{}".format(self.name, address)
        sock.sendto(bytes(data, "utf-8"), (self.MCAST_GROUP, self.MCAST_PORT))

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multicast IP Announcer")
    parser.add_argument('nickname', type=str)
    parser.add_argument('-ipv6', type=str2bool, nargs='?', const=True, default=False, help='Enable IPv6 IP Reporting')
    args = vars(parser.parse_args())
    MCAClient = MulticastAnnouncerClient(**args)


