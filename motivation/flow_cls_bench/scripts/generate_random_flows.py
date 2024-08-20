import random

def random_bytes(count):
    x = [random.randrange(0, 256) << (8 * x) for x in range(count)]
    r = 0
    for a in x:
        r |= a
    return r

def rand_ip():
    return random_bytes(4)

def rand_port():
    return random_bytes(2)

def main():
    flow_set = set()
    count_flows = 100000
    # print('{')
    for i in range(count_flows):
        while True:
            # saddr = rand_ip()
            # daddr = rand_ip()
            source = rand_port()
            dest = rand_port()
            # proto = 17 # IPPROTO_UDP
            t = (source, dest)
            if t in flow_set:
                # repeat
                continue
            flow_set.add(t)
            break

        # print(f'{{0x{saddr:x}, {source}, 0x{daddr:x}, {dest}, {proto}}},')
        print(f'{source} {dest}')
    # print('};')


if __name__ == '__main__':
    main()
