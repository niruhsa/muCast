#!/usr/bin/python3
import socket, struct, netifaces, ipaddress, codecs, sys, time, threading, logging
from netaddr import IPAddress, IPNetwork

class MulticastAnnouncerListener:

    def __init__(self, **kwargs):
        self.MCAST_GROUP = '224.1.1.1'
        self.MCAST_PORT = 4180
        self.IS_ALL_GROUPS = True
        self.blacklisted_interfaces = [ 'lo', 'lo0' ]
        self.blacklisted_ips = []
        self.localSubnets = []
        self.ips = {}
        self.logfile = kwargs['o']
        self.seperator = kwargs['s']
        self.verbose = kwargs['v']
        self.name = kwargs['nickname']
        
        self.log = logging.getLogger(__name__)
        syslog = logging.StreamHandler()

        formatter = logging.Formatter("%(message)s")
        syslog.setFormatter(formatter)
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(syslog)
        self.log = logging.LoggerAdapter(self.log, { 'app_name': 'muCast' })

        if not self.logfile: self.log.debug("[ OK ] Writing to stdout")
        else: self.log.debug('[ OK ] Writing to logfile: {}'.format(self.logfile))

        sys.stdout.flush()
        sys.stderr.flush()

        localSubnets = threading.Thread(target=self.getLocalSubnets, args=()).start()
        receive = threading.Thread(target=self.receive, args=()).start()

    def getLocalSubnets(self):
        while True:
            blacklisted_ips = []
            localSubnets = []
            for inter in netifaces.interfaces():
                if inter not in self.blacklisted_interfaces:
                    interface = netifaces.ifaddresses(inter)
                    for address in interface:
                        blacklisted_ips.append(interface[address][0]['addr'])
                        try:
                            bits = None
                            ip_addr = None

                            if 'netmask' in interface[address][0].keys():
                                netmask = interface[address][0]['netmask']
                                bits = IPAddress(netmask).netmask_bits()
                            if 'addr' in interface[address][0].keys():
                                ip_addr = interface[address][0]['addr']

                            cidr = "{}/{}".format(ip_addr, bits)
                            localSubnets.append(ipaddress.ip_network(cidr, False))
                        except Exception as e: continue
            self.blacklisted_ips = blacklisted_ips
            self.localSubnets = localSubnets
            time.sleep(1)

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
            packet_id = recv.split(":")[2]
            timestamp = recv.split(":")[3]
            if self.verbose:
                self.log.debug("[VERBOSE] Packet {} from {} with content {} received at {} ({} difference in ms)".format(packet_id, nickname, address, timestamp, ((time.time() - float(timestamp)) / 1000)), file=sys.stderr)
            for subnet in self.localSubnets:
                subnet = IPNetwork(str(subnet))
                ip = IPAddress(str(address))
                if ip in subnet and nickname != self.name:
                    self.ips[nickname] = address
                    if self.logfile: self.writeLogFile()
                    self.log.info(codecs.decode(("{}{}{}".format(address, self.seperator, nickname)), 'unicode_escape'))
        except Exception as e: pass

    def writeLogFile(self):
        with open(self.logfile, 'w') as file:
            file_content = ""
            for nickname in self.ips:
                ip = self.ips[nickname]
                file_content += "{}{}{}\n".format(ip, self.seperator, nickname)
            file.write(codecs.decode(file_content, 'unicode_escape'))
            file.close()
