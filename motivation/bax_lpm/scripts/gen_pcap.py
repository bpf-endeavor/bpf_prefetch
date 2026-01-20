#! /usr/bin/python3
"""
Generate a pcap file to be used by the workload generator
(DPDK Burst Replay)
"""
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from argparse import ArgumentParser
import random
import string
import math
import sys

# NOTE: this script relies on following config
src_mac = '0c:42:a1:dd:59:24'
dst_mac = '0c:42:a1:e2:a6:a0'
input_file = '../dataset/ipv4.txt'
src_ip = '192.168.1.2'
dst_ip = '192.168.1.1'
zipf_parameter = 0.0
src_port = 3030
dst_port = 8080

# used for defining the payload of UDP packets
# random_table = ''.join(random.choices(string.ascii_lowercase, k=1500))

# used in the payload of UDP packets
table = []


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


def create_pcap_file(n, r, output):
    payload = 'hello world\n'
    pkts = []
    print('Notice: the source/dest ip address is hardcoded')
    print('src ip:', src_ip)
    print('dst ip:', dst_ip)

    print('Notice: the random number generator seed is set to a fix value')
    random.seed(127)

    if n <= 0:
        n = len(table)

    MSS = 1440
    z = Zipf(n, zipf_parameter)
    I.prime()
    for i in range(r):
        # payload_size = math.ceil(random.paretovariate(3) * MSS)
        # payload = random_table[0:payload_size]

        selectd_query = z.sample()
        payload = table[selectd_query]

        pkt = form_packet(src_ip, src_port, dst_ip, dst_port, payload)
        pkts.append(pkt)
        I()
    I.out()

    wrpcap(output, pkts)
    print(f'Generated a pcap file with {r} record using {n} flows')


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--num-flows', '-n', default=1 << 15, type=int, help='number of flows used in pcap file. use -1 for using all rules in the table')
    parser.add_argument('--num-records', '-r', default=300000, type=int, help='number of records in pcap file')
    parser.add_argument('--output', '-o', default='test.pcap', type=str, help='output file path')
    args = parser.parse_args()

    if args.num_flows > args.num_records:
        print('You have request more flows than total flows in the file!')
        sys.exit(1)
    return args


def ipv4_to_int(ip_string):
    """
    Converts an IPv4 string (e.g., '192.168.1.1') to a 32-bit integer.
    """
    # Split the string into four parts
    octets = ip_string.split('.')

    # Calculate the integer value using bitwise shifts
    # Octet 1: shift left 24 bits
    # Octet 2: shift left 16 bits
    # Octet 3: shift left 8 bits
    # Octet 4: shift left 0 bits
    ip_int = (int(octets[0]) << 24) + \
             (int(octets[1]) << 16) + \
             (int(octets[2]) << 8) + \
             int(octets[3])

    return ip_int


def parse_input_and_fill_table():
    with open(input_file, 'r') as F:
        for line in F:
            try:
                net, range = line.strip().split('/')
                range = int(range)
                if range == 32:
                    table.append(net)
                else:
                    # select a concerete instance of that IP range
                    # TODO: maybe I need to do this better ...
                    instance = net[:-1] + '1'
                    val = ipv4_to_int(instance)
                    val = val.to_bytes(4, byteorder='big')
                    table.append(val)
            except ValueError as e:
                print(e)
                continue

if __name__ == "__main__":
    args = parse_args()
    print('Notice: the source/dest MAC address is hardcoded')
    print('src mac:', src_mac)
    print('dst mac:', dst_mac)
    parse_input_and_fill_table()

    if args.num_flows > len(table):
        print('You requested more distinct flows than what exists in our table')
        sys.exit(1)

    create_pcap_file(args.num_flows, args.num_records, args.output)
