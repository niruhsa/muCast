import socket, struct, netifaces, ipaddress
from netaddr import IPAddress

class MulticastAnnouncerListener:

    def __init__(self):
        self.MCAST_GROUP = '224.1.1.1'
        self.MCAST_PORT = 4180
        self.IS_ALL_GROUPS = True
        self.blacklisted_interfaces = [ 'lo', 'lo0' ]
        self.localSubnets = []

        self.getLocalSubnets()
        self.receive()

    def getLocalSubnets(self):
        for inter in netifaces.interfaces():
            if inter not in self.blacklisted_interfaces:
                interface = netifaces.ifaddresses(inter)
                for address in interface:
                    try:
                        bits = None
                        ip_addr = None

                        if 'netmask' in interface[address][0].keys():
                            netmask = interface[address][0]['netmask']
                            bits = IPAddress(netmask).netmask_bits()
                        if 'addr' in interface[address][0].keys():
                            ip_addr = interface[address][0]['addr']

                        cidr = "{}/{}".format(ip_addr, bits)
                        self.localSubnets.append(ipaddress.ip_network(cidr, False))
                    except: pass

    def receive(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.IS_ALL_GROUPS: sock.bind(('', self.MCAST_PORT))
        else: socket.bind((self.MCAST_GROUP, self.MCAST_PORT))

        mreq = struct.pack("4sl", socket.inet_aton(self.MCAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        while True:
            recv = sock.recv(10240).decode("utf-8")
            self.parseResponse(recv)

    def parseResponse(self, recv):
        try:
            nickname = recv.split(":")[0]
            address = ipaddress.ip_address(recv.split(":")[1])
            for subnet in self.localSubnets:
                if address in subnet.hosts(): sys.stdout.write(recv)
        except: pass

if __name__ == "__main__": MCAListener = MulticastAnnouncerListener()
