"""
Clean the histogram report to understand how much of a
batch is active when we walk through the Treap.
"""
import re

def report(samples):
    N = len(samples)
    keys = list(sorted(samples[0].keys()))
    for k in keys:
        vals = sorted([s[k] for s in samples])
        q1 = vals[int(N * 0.25)]
        q2 = vals[int(N * 0.50)]
        q3 = vals[int(N * 0.75)]
        iqr = round(q3 - q1, ndigits=1)
        print(f'@bucket {k}: {q2}% (+- {iqr})')

def convert_to_percentage(data):
    new = {}
    total_pkts = sum([v for v in data.values()])
    keys = sorted(data.keys())
    for k in keys:
        p = round((data[k] / total_pkts) * 100, ndigits=1)
        new[k] = p
    return new

def main():
    samples = []
    data = {}
    r = re.compile('@bucket (\d+): (\d+)')
    try:
        while True:
            line = input().strip()
            if (not line or '@bucket' not in line):
                if data:
                    # if data has entries and our line does not have a report
                    # enough it means the report sequence has ended
                    ndata = convert_to_percentage(data)
                    samples.append(ndata)
                    data.clear()
                continue
            res = r.search(line)
            # print(res, line)
            key = int(res.group(1))
            val = int(res.group(2))
            data[key] = val
            continue
    except EOFError:
        pass

    if data:
        ndata = convert_to_percentage(data)
        samples.append(ndata)
        data.clear()

    report(samples)


main()
