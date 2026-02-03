#! python3
from subprocess import check_output, PIPE


def get_tput_samples(file_path):
    cmd = f'cat {file_path} | grep recv'
    res = check_output(cmd, shell=True)
    res = res.decode()
    lines = [t.strip().split(': ')[1] for t in res.split('\n') if t.strip()]
    nums = [float(f) for f in lines]
    return nums


def main():
    result_dir = './results'
    modes = ['baseline', 'bax']
    # TODO: '1' for some reason I'm measing measurements for 1
    flows = ['10','100','1000','10000','100000','1000000','2000000','4000000', '6000000', '8000000']
    zipf = ['0', '0.5', '1.0', '1.5', '2']

    print('Throughput in different modes and zipf distributions')
    print('with variable number of flows')
    for z in zipf:
        for mode in modes:
            tput = []
            for f in flows:
                file_path = f'{result_dir}/{mode}/load_{f}_{z}.txt'
                samples = get_tput_samples(file_path)
                index = 7

                t = samples[index]
                tput.append(t)
            print(f'{mode}@{z}:', tput)
    print('-------')
    print('x Axis:', flows)

if __name__ == '__main__':
    main()

