"""
Generate a pcap file to be used by the workload generator
(DPDK Burst Replay)
"""
import os
import sys
import random
import string
from multiprocessing import Pool
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from argparse import ArgumentParser
# curdir = os.path.abspath(os.path.dirname(sys.argv[0]))
# common_lib_dir = os.path.join(curdir, '../../../libs/common/')
# sys.path.insert(0, common_lib_dir)
# from zipf import Zipf
# from progress_indicator import ProgIndicator

src_mac = '9c:dc:71:5c:8f:d1'
dst_mac = '9c:dc:71:5c:9f:11'
src_ip = '192.168.1.2'
dst_ip = '192.168.1.1'
# payload = 'hello world\n'

def random_name(k, max_len):
    valid_char = string.ascii_lowercase + string.ascii_uppercase + string.digits
    N = set()
    while len(N) < k:
        r = ''.join(random.choices(valid_char, k=max_len))
        if r in N:
            continue
        N.add(r)
    return list(N)

def get_head(host):
    payload_head = f'GET / HTTP/1.1\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\nHost: {host}.it\r\n\r\n'
    return payload_head

# FLOW_FILE = '../flows.txt'
# I = ProgIndicator()


def parse_args():
    parser = ArgumentParser()
    # parser.add_argument('--num_flows', '-n', default=100, type=int, help='number of flows inside the pcap file')
    parser.add_argument('--output', '-o', default='test.pcap', type=str, help='output file path')
    # parser.add_argument('--zipf', '-z', default=2.0, type=float, help='zipf alpha (only in full mode)')
    # parser.add_argument('--full_mode', '-F', action='store_true', help='Use full working set but different patterns (zipf)')
    args = parser.parse_args()
    return args


def form_packet(saddr: str, source: int, daddr: str, dest: int, payload: str):
    eth_header = Ether(src=src_mac, dst=dst_mac)
    ip_header = IP(src=saddr, dst=daddr, ttl=64)
    udp_header = UDP(dport=dest, sport=source)
    packet = eth_header / ip_header / udp_header / Raw(load=payload)

    packet[IP].chksum = None
    packet[UDP].chksum = None
    return packet


def _prepare_packets(name):
    # size = 0
    # body = ''.join(random.choices(string.ascii_lowercase, k=size))
    body = ''
    payload = get_head(name) + body + '\r\n\r\n'
    t = form_packet(src_ip, 3000, dst_ip, 8080, payload)
    return t


def create_pcap_file(n, output):
    random.seed(127)
    # pkts = []
    names = random_name(n, 5)
    print('got all the names')
    with Pool(10) as p:
        pkts = p.map(_prepare_packets, names)
    # for i in range(n):
    #     size = 0
    #     body = ''.join(random.choices(string.ascii_lowercase, k=size))
    #     payload = get_head(names[i]) + body + '\r\n\r\n'
    #     t = form_packet(src_ip, 3000, dst_ip, 8080, payload)
    #     pkts.append(t)
    print('Start writing the pcap file...')
    wrpcap(output, pkts)
    print('Generated a pcap file with', n, 'flows')


# def create_pcap_all_flows_zipf(output, count_record=100000, zipf_s=2):
#     with open(FLOW_FILE, 'r') as f:
#         # src, dst port
#         flows = [tuple(map(int, line.split())) for line in f.readlines()]
#     count_flow = len(flows)
#     z = Zipf(count_flow - 1, zipf_s)
#     pkts = []
#     I.prime()
#     for i in range(count_record):
#         flow_index = z.sample()
#         flow = flows[flow_index]
#         a, b = flow
#         pkt = form_packet(src_ip, a, dst_ip, b, payload)
#         pkts.append(pkt)
#         I()
#     I.out()
#     wrpcap(output, pkts)
#     print('Generated a pcap file with', i, 'records. Zipf=', zipf_s,
#             'working set=', count_flow)


if __name__ == "__main__":
    args = parse_args()
    print('Notice: the source/dest MAC address is hardcoded')
    print('src mac:', src_mac)
    print('dst mac:', dst_mac)
    print('Notice: the source/dest IP address is hardcoded')
    # if args.full_mode:
    #     r = 300*1000
    #     create_pcap_all_flows_zipf(args.output, r, args.zipf)
    # else:
    #     create_pcap_file(args.num_flows, args.output)
    create_pcap_file(500000, args.output)
