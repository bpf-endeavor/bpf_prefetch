"""
Generate a pcap file to be used by the workload generator
(DPDK Burst Replay)
"""
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from argparse import ArgumentParser
import random
import string
import math

src_mac = 'b8:ce:f6:d2:12:c6'
dst_mac = 'e8:eb:d3:a7:0c:b6'


# used for defining the payload of UDP packets
random_table = ''.join(random.choices(string.ascii_lowercase, k=1500))


class Zipf:
    def __init__(self, n, s):
        # Commulative probabilities
        self.c_probs = [0.0 for i in range(n+1)]
        # Harmonic
        h = 0
        # Also called alpha
        self.s = s
        #  Number of ranks
        self.n = n

        for i in range(1, n+1):
            h += 1.0 / (i ** s)

        self.c_probs[0] = 0
        for i in range(1, n+1):
            self.c_probs[i] = self.c_probs[i - 1] + (1.0 / ((i ** s) * h));

    def sample(self):
        rnd = random.random()
        low = 1
        high = self.n
        while low <= high:
            mid = int((low + high) / 2)
            if rnd > self.c_probs[mid - 1] and rnd <= self.c_probs[mid]:
                return mid
            if self.c_probs[mid] < rnd:
                low = mid + 1
            else:
                high = mid - 1
        raise Exception('This must not happen')


class ProgIndicator:
    def __init__(self):
        self.prime()

    def prime(self):
        self.state = 0
        self.count = 0
        self.first = True

    def out(self):
        print('\r                    ')

    def __call__(self):
        x = '/-\|-\|'
        c = x[self.state]
        self.count += 1
        self.state = (self.state + 1) % len(x)

        if self.count % (701) != 1:
            return

        if self.first:
            self.first = False
            s = f'\n{c}'
        else:
            s = f'\r{c}'
        s += f' {self.count}'
        print(s, end='', sep='')

I = ProgIndicator()


def form_packet(saddr: str, source: int, daddr: str, dest: int, payload: str):
    eth_header = Ether(src=src_mac, dst=dst_mac)
    ip_header = IP(src=saddr, dst=daddr, ttl=64)
    udp_header = UDP(dport=dest, sport=source)
    packet = eth_header / ip_header / udp_header / Raw(load=payload)

    packet[IP].chksum = None
    packet[UDP].chksum = None
    return packet


def create_pcap_file(n, output):
    payload = 'hello world\n'
    pkts = []
    src_ip = '192.168.200.101'
    dst_ip = '192.168.200.102'
    print('Notice: the source/dest ip address is hardcoded')
    print('src ip:', src_ip)
    print('dst ip:', dst_ip)

    print('Notice: the random number generator seed is set to a fix value')
    random.seed(127)

    MSS = 1440
    PORT_RANGE = (0, 1 << 15)
    z = Zipf(PORT_RANGE[1], 2)
    I.prime()
    for i in range(n):
        src_port = 3030
        dst_port = z.sample()
        payload_size = math.ceil(random.paretovariate(3) * MSS)
        payload = random_table[0:payload_size]
        pkt = form_packet(src_ip, src_port, dst_ip, dst_port, payload)
        pkts.append(pkt)
        I()
    I.out()

    wrpcap(output, pkts)
    print('Generated a pcap file')


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--num-records', '-n', default=300000, type=int, help='number of records in pcap file')
    parser.add_argument('--output', '-o', default='test.pcap', type=str, help='output file path')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    print('Notice: the source/dest MAC address is hardcoded')
    print('src mac:', src_mac)
    print('dst mac:', dst_mac)
    create_pcap_file(args.num_records, args.output)
