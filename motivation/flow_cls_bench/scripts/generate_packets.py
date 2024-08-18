"""
Generate a pcap file to be used by the workload generator
(DPDK Burst Replay)
"""
from scapy.all import Ether, IP, UDP, Raw, wrpcap

#   SRC IP       SPORT  DST IP      DPORT  PROTO
src_mac = 'f2:66:f2:6a:84:53'
dst_mac = '4e:10:16:67:71:23'

def form_packet(saddr: str, source: int, daddr: str, dest: int, payload: str):
    eth_header = Ether(src=src_mac, dst=dst_mac)
    ip_header = IP(src=saddr, dst=daddr, ttl=64)
    udp_header = UDP(dport=dest, sport=source)
    packet = eth_header / ip_header / udp_header / Raw(load=payload)

    packet[IP].chksum = None
    packet[UDP].chksum = None
    return packet


def create_pcap_file():
    payload = 'hello world\n'
    pkts = []
    src_ip = '192.168.200.101'
    dst_ip = '192.168.200.102'
    with open('../flows.txt', 'r') as f:
        for line in f:
            a, b = map(int, line.split())
            pkt = form_packet(src_ip, a, dst_ip, b, payload)
            pkts.append(pkt)
    wrpcap("test.pcap", pkts)


if __name__ == "__main__":
    print('Notice: the source/dest MAC address is hardcoded')
    print('src mac:', src_mac)
    print('dst mac:', dst_mac)
    create_pcap_file()
