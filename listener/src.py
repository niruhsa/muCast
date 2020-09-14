import socket, struct, netifaces, ipaddress, argparse, codecs
from netaddr import IPAddress, IPNetwork

class MulticastAnnouncerListener:

    def __init__(self, **kwargs):
        self.MCAST_GROUP = '224.1.1.1'
        self.MCAST_PORT = 4180
        self.IS_ALL_GROUPS = True
        self.blacklisted_interfaces = [ 'lo', 'lo0' ]
        self.localSubnets = []
        self.ips = {}
        self.logfile = kwargs['o']
        self.seperator = kwargs['s']
        self.verbose = kwargs['v'][0]

        if self.verbose <= 0 or self.verbose > 3: print('[ERROR] Verbosity has to be between 1-3 1 being the most verbose, 3 being the least')

        if not self.logfile: print("[ OK ] Writing to stdout")
        else: print('[ OK ] Writing to logfile: {}'.format(self.logfile))

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
        if self.verbose == 1: print('[TRACE] {}'.format(recv))
        try:
            nickname = recv.split(":")[0]
            address = ipaddress.ip_address(recv.split(":")[1])
            for subnet in self.localSubnets:
                subnet = IPNetwork(str(subnet))
                ip = IPAddress(str(address))
                if ip in subnet:
                    self.ips[nickname] = address
                    if self.verbose <= 2: print('[DEBUG] {}'.format(recv))
                    if self.logfile:
                        if self.verbose <= 3: print(codecs.decode(("{}{}{}".format(nickname, self.seperator, address)), 'unicode_escape'))
                        self.writeLogFile()
                    else:
                        if self.verbose <= 3: print(codecs.decode(("{}{}{}".format(nickname, self.seperator, address)), 'unicode_escape'))
        except Exception as e: pass

    def writeLogFile(self):
        with open(self.logfile, 'w') as file:
            file_content = ""
            for nickname in self.ips:
                ip = self.ips[nickname]
                file_content += "{}{}{}\n".format(nickname, self.seperator, ip)
            file.write(codecs.decode(file_content, 'unicode_escape'))
            file.close()

if __name__ == "__main__": 
    parser = argparse.ArgumentParser(description="Multicast IP Announcer")
    parser.add_argument('-o', nargs='?', const=True, default=False, help='Write to logfile instead of /dev/stdout')
    parser.add_argument('-s', nargs='?', const=True, default=":", help='Character for the nickname<seperator>ip format, by default this seperator is ":"')
    parser.add_argument('-v', type=int, nargs=1, default='3', help='What verbosity level to use, 1 = Everything received, 2 = Everything filtered, 3 = Everything formatted, default is 3.')
    args = vars(parser.parse_args())
    MCAListener = MulticastAnnouncerListener(**args)
