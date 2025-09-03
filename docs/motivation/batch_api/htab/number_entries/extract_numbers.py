#!/usr/bin/python
import os


def read_file(file_path):
    with open(file_path, 'r') as f:
        sum = 0
        count = 0
        next(f) # skip first line
        for line in f.readlines():
            tput = float(line.split(' ')[-1].strip()) #kpps
            sum += tput
            count += 1
    tput = sum / count
    return tput


def main():
    data = {}

    # assuming the script is ran from the current dir :)
    data_dir = './data'
    exps = os.listdir(data_dir)
    for exp in exps:
        exp_dir = os.path.join(data_dir, exp)
        files = os.listdir(exp_dir)
        measurements = []
        for fname in files:
            entries = int(fname.split('.')[0])
            file_path = os.path.join(exp_dir, fname)
            try:
                tput = read_file(file_path)
            except:
                tput = -1
            measurements.append((entries, tput))

        data[exp] = measurements

    for exp, measurements in data.items():
        measurements.sort(key=lambda x: x[0])
        print(exp)
        X = [round(t[0], 2) for t in measurements]
        Y = [round(t[1], 2) for t in measurements]
        print('x:', X)
        print('y:', Y)


if __name__ == "__main__":
    main()

