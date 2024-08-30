import os
import sys
import subprocess
from argparse import ArgumentParser


xdpfilter = './xdp-tools/xdp-filter/xdp-filter'


class ProgIndicator:
    def __init__(self):
        self.prime()

    def prime(self):
        self.state = 0
        self.count = 0
        self.first = True

    def __call__(self):
        x = '/-\|-\|'
        c = x[self.state]
        self.count += 1
        self.state = (self.state + 1) % len(x)

        if self.count % (5) != 1:
            return

        if self.first:
            self.first = False
            s = f'\n{c}'
        else:
            s = f'\r{c}'
        s += f' {self.count}'
        print(s, end='', sep='')

I = ProgIndicator()


def filter_unload():
    cmd = [xdpfilter, 'unload', '--all']
    subprocess.run(cmd)


def filter_install(iface):
    checkpoint = os.path.abspath(os.curdir)
    os.chdir(os.path.dirname(xdpfilter))
    # Load the XDP program on the interface
    cmd = ['./xdp-filter', 'load', '-f', 'udp', '-m', 'native', '-p', 'allow', iface]
    subprocess.check_output(cmd)

    # Insert some rules
    I.prime()
    for x in range(0, 1 << 15):
        cmd = ['./xdp-filter', 'port', '-p', 'udp', '-m', 'dst', str(x)]
        subprocess.check_output(cmd)
        I()

    os.chdir(checkpoint)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--unload', help='Unload the filter', action='store_true')
    args = parser.parse_args()
    return args


def main():
    if os.geteuid() != 0:
        print('Run this script as root')
        print('Example: sudo NET_IFACE=eth0', sys.argv[0])
        sys.exit(0)

    if not os.path.isfile(xdpfilter):
        raise Exception('Did not found the xdp-filter program')

    args = parse_args()

    iface = os.environ.get('NET_IFACE', None)
    if iface is None:
        print('NET_IFACE is not set!')
        sys.exit(-1)
    print('Interface:', iface)

    print('Unload previous filters')
    filter_unload()
    if args.unload:
        return
    print('Installing a new filter ...')
    filter_install(iface)

    print('Start workload generator ...')


if __name__ == '__main__':
    main()
