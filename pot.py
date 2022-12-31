import sys
import argparse
from datetime import datetime

from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
from twisted.names import dns
from twisted.names import client, server

# we use twisted name library to implement custom
# dns server that will be a honeypot

class HoneyDNS(server.DNSServerFactory):
    request_log = {}
    opts = None
    def messageReceived(self, message, proto, address=None):
        entry = {}
        entry["src_ip"] = address[0]
        entry["src_port"] = address[1]
        entry["dns_name"] = message.queries[0].name.name
        entry["dns_type"] = dns.QUERY_TYPES.get(message.queries[0].type, dns.EXT_QUERIES.get(message.queries[0].type, "UNKNOWN (%d)" % message.queries[0].type))
        entry["dns_cls"] = dns.QUERY_CLASSES.get(message.queries[0].cls, "UNKNOWN (%d)" % message.queries[0].cls)
        self.log(entry)

        if entry["src_ip"] in self.request_log and (datetime.now() - self.request_log[entry["src_ip"]]["last_seen"]).total_seconds() < self.opts.req_timeout:
            if self.request_log[entry["src_ip"]]["count"] < self.opts.req_count:
                self.request_log[entry["src_ip"]]["count"] += 1
                self.request_log[entry["src_ip"]]["last_seen"] = datetime.now()
                return server.DNSServerFactory.messageReceived(self, message, proto, address)
            else:
                self.request_log[entry["src_ip"]]["last_seen"] = datetime.now()
        else:
            self.request_log[entry["src_ip"]] = {"count": 1, "last_seen": datetime.now()}
            return server.DNSServerFactory.messageReceived(self, message, proto, address)
    
    def log(self, dns_details):
        # here add logging functionality

parser = argparse.ArgumentParser()
parser.add_argument("server", type=str, help="DNS server IP address")
parser.add_argument("-p", "--dns-port", type=int, default=5053, help="DNS honeypot port")
parser.add_argument("-c", "--req-count", type=int, default=3, help="how many request to resolve")
parser.add_argument("-t", "--req-timeout", type=int, default=86400, help="timeout to re-start resolving requests")
opts = parser.parse_args()

verbosity = 3

resolver = client.Resolver(server=[(opts.server, 53)])
factory = HoneyDNS(client=[resolver], verbose = verbosity)
factory.opts = opts
protocol = dns.DNSDatagramProtocol(factory)
factory.noisy = protocol.noisy = verbosity

reactor.listenUDP(opts.dns_port, protocol)
reactor.listenTCP(opts.dns_port, factory)
reactor.run()