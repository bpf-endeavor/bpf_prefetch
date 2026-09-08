#!/usr/bin/env python3

"""
Generate PCAP files for DPDK Burst Replay.

Generates one PCAP for each Zipf parameter:
    0, 0.5, 1, 1.5, 2
"""

from scapy.all import Ether, IP, UDP, Raw, wrpcap
from argparse import ArgumentParser
import ipaddress
import random
import os
import sys


ZIPF_PARAMETERS = [0.0, 0.5, 1.0, 1.5, 2.0]

INPUT_FILE = "../dataset/ipv4.txt"

SRC_IP = "192.168.1.2"
DST_IP = "192.168.1.1"

SRC_PORT = 3030
DST_PORT = 8080

table = []


class Zipf:
    def __init__(self, n, s):
        self.c_probs = [0.0 for _ in range(n + 1)]
        self.n = n
        self.s = s

        h = 0.0
        for i in range(1, n + 1):
            h += 1.0 / (i ** s)

        for i in range(1, n + 1):
            self.c_probs[i] = (
                self.c_probs[i - 1]
                + 1.0 / ((i ** s) * h)
            )

    def sample(self):
        """
        Return a ZERO-BASED index in [0, n-1].
        """
        rnd = random.random()

        low = 1
        high = self.n

        while low <= high:
            mid = (low + high) // 2

            if self.c_probs[mid - 1] < rnd <= self.c_probs[mid]:
                return mid - 1

            if self.c_probs[mid] < rnd:
                low = mid + 1
            else:
                high = mid - 1

        raise RuntimeError("Zipf sampling failed")


def parse_args():
    parser = ArgumentParser()

    parser.add_argument(
        "--src-mac",
        required=True,
        help="MAC address of workload-generator NIC",
    )

    parser.add_argument(
        "--dst-mac",
        required=True,
        help="MAC address of DUT NIC",
    )

    parser.add_argument(
        "--num-flows",
        "-n",
        default=1 << 15,
        type=int,
        help="number of routing entries used; -1 means all entries",
    )

    parser.add_argument(
        "--num-records",
        "-r",
        default=300000,
        type=int,
        help="number of packets in each PCAP",
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default=".",
        help="directory where generated PCAP files are written",
    )

    parser.add_argument(
        "--input-file",
        default=INPUT_FILE,
        help=f"routing table file (default: {INPUT_FILE})",
    )

    return parser.parse_args()


def parse_input_and_fill_table(input_file):
    table.clear()

    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                network = ipaddress.IPv4Network(line, strict=False)

                # Pick a concrete IP address belonging to this prefix.
                if network.prefixlen == 32:
                    address = network.network_address
                else:
                    address = network.network_address + 1

                # The XDP program consumes the first four bytes of the
                # UDP payload as the lookup address.
                table.append(address.packed)

            except ValueError as e:
                print(f"Skipping invalid entry {line!r}: {e}")


def form_packet(src_mac, dst_mac, payload):
    eth_header = Ether(
        src=src_mac,
        dst=dst_mac,
    )

    ip_header = IP(
        src=SRC_IP,
        dst=DST_IP,
        ttl=64,
    )

    udp_header = UDP(
        sport=SRC_PORT,
        dport=DST_PORT,
    )

    packet = eth_header / ip_header / udp_header / Raw(load=payload)

    packet[IP].chksum = None
    packet[UDP].chksum = None

    return packet


def create_pcap_file(
    num_flows,
    num_records,
    zipf_parameter,
    output,
    src_mac,
    dst_mac,
):
    print()
    print(f"Generating {output}")
    print(f"  Zipf alpha : {zipf_parameter}")
    print(f"  Flows      : {num_flows}")
    print(f"  Packets    : {num_records}")

    # Same traffic sequence for reproducibility.
    random.seed(127)

    z = Zipf(num_flows, zipf_parameter)

    packets = []

    for i in range(num_records):
        selected_query = z.sample()
        payload = table[selected_query]

        packet = form_packet(
            src_mac,
            dst_mac,
            payload,
        )

        packets.append(packet)

        if (i + 1) % 10000 == 0:
            print(
                f"\r  generated {i + 1}/{num_records}",
                end="",
                flush=True,
            )

    print()

    wrpcap(output, packets)

    print(f"  wrote: {output}")


def zipf_filename(alpha):
    # 0.0 -> 0
    # 1.0 -> 1
    # 0.5 -> 0.5
    if alpha.is_integer():
        return str(int(alpha))

    return str(alpha)


def main():
    args = parse_args()

    if not os.path.isfile(args.input_file):
        print(
            f"Input routing table does not exist: {args.input_file}",
            file=sys.stderr,
        )
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    print("Configuration:")
    print(f"  source MAC : {args.src_mac}")
    print(f"  dest MAC   : {args.dst_mac}")
    print(f"  source IP  : {SRC_IP}")
    print(f"  dest IP    : {DST_IP}")
    print(f"  input file : {args.input_file}")

    parse_input_and_fill_table(args.input_file)

    print(f"  routes     : {len(table)}")

    if not table:
        print("No valid routes were found.", file=sys.stderr)
        sys.exit(1)

    if args.num_flows <= 0:
        num_flows = len(table)
    else:
        num_flows = args.num_flows

    if num_flows > len(table):
        print(
            f"Requested {num_flows} flows, "
            f"but dataset only contains {len(table)} routes.",
            file=sys.stderr,
        )
        sys.exit(1)

    if num_flows > args.num_records:
        print(
            "Number of flows cannot exceed number of packets.",
            file=sys.stderr,
        )
        sys.exit(1)

    for alpha in ZIPF_PARAMETERS:
        alpha_name = zipf_filename(alpha)

        output = os.path.join(
            args.output_dir,
            f"lpm_zipf_{alpha_name}.pcap",
        )

        create_pcap_file(
            num_flows=num_flows,
            num_records=args.num_records,
            zipf_parameter=alpha,
            output=output,
            src_mac=args.src_mac,
            dst_mac=args.dst_mac,
        )


if __name__ == "__main__":
    main()
