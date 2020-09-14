from client.src import MulticastAnnouncerClient
from listener.src import MulticastAnnouncerListener
import argparse

class Master:

    def __init__(self, **kwargs):
        self.args = kwargs
        self.MCAClient = MulticastAnnouncerClient(**self.args)
        self.MCAListener = MulticastAnnouncerListener(**self.args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multicast IP Announcer")
    parser.add_argument('nickname', type=str)
    parser.add_argument('-ipv6', nargs='?', const=True, default=False, help='Enable IPv6 IP Reporting')
    parser.add_argument('-timer', type=int, nargs='?', const=True, default=30, help='How long it should wait before rebroadcasting all IPs if no changes are detected in seconds')
    parser.add_argument('-v', nargs='?', const=True, default=False, help='Enable verbose logging of the packets sent')
    parser.add_argument('-o', nargs='?', const=True, default=False, help='Write to logfile instead of /dev/stdout')
    parser.add_argument('-s', nargs='?', const=True, default=":", help='Character for the nickname<seperator>ip format, by default this seperator is ":"')
    args = vars(parser.parse_args())
    master = Master(**args)
    