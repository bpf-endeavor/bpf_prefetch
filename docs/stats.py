#! /usr/bin/python3
import sys
import math

count_args = len(sys.argv)
FILE='-'
if count_args > 1:
    FILE=sys.argv[1]

if FILE == '-':
    stream = sys.stdin
else:
    stream = open(FILE, 'r')

samples = []
for i, line in enumerate(stream):
    line = line.strip()
    if not line:
        continue
    try:
        v = float(line)
    except:
        print('failed to convert to fload: sample at line', i)
        continue
    samples.append(v)
stream.close()

samples.sort()
count_smaples = len(samples)
if count_smaples < 1:
    print('No samples found', file=sys.stderr)
    sys.exit(1)
mean = sum(samples) / count_smaples
print('samples:', count_smaples)
print('max:', max(samples))
print('min:', min(samples))
print(f'mean: {mean:.2f}')
print('@1 :', samples[int(count_smaples * 0.01)])
print('@50:', samples[int(count_smaples * 0.50)])
print('@99:', samples[int(count_smaples * 0.99)])
print('@99.9:', samples[int(count_smaples * 0.999)])


N = count_smaples
std = math.sqrt( (1 / (N - 1)) * sum([(x - mean) ** 2 for x in samples]))
std_err = std / math.sqrt(N)
print(f'std: {std:.3f}')
print(f'standard err: {std_err:.3f}')


# Reporting median (+-) iqr
q1 = samples[int(N * 0.25)]
q2 = samples[int(N * 0.50)]
q3 = samples[int(N * 0.75)]
iqr = q3 - q1
whisker =  iqr * 1.5
upper_bound = q3 + whisker
lower_bound = q1 - whisker
print (f'median (iqr): {q2} ({iqr})')
print (f'box-plot: {lower_bound:.2f}--[{q1}-|{q2}|-{q3}]--{upper_bound:.2f}')


no_outlier = list(filter(lambda x: x <= upper_bound and x >= lower_bound, samples))
d1 = q2 - no_outlier[0]
d2 = no_outlier[-1] - q2
r = max(d1, d2)
print (f'meidan +- range: {q2} +- {r}')
