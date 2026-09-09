## Commands

Generate workload:
	use script for generating pcap file from `flows.txt` file (100 flows and 5000 flows)
	use dpdk-burst-reply to generate traffic.

Measure cache miss:
	sudo perf stat -C 17 -e cycles -e  instructions -e cache-references -e cache-misses -e L1-dcache-loads -e L1-dcache-load-misses -r 3  -- sleep 1


## Setup

I loaded an XPD program with a hash MAP.
I loaded the hash MAP with 5000 entries.
I generated traffic with DPDK.
In one case only 100 of entries where queried.
In the other case 5000 of entries where queried.
All the query traffic where mapped to one queue


## Notes

### Note 1

|Mode      | Tput (Mpps) | LLC miss/s | L1 Miss (M miss/s) |
|:---------|:------------|:-----------|:-------------------|
|100-flows | 6.64        | 2839       | 58.6               |
|5000-flows| 6.27        | 2813       | 70.5               |

Although majority of of memory accesses hit in the last level cache (LLC), the
increase in the L1 cache miss has decreased the performance of the NF
considerably (5.57% or 370 Kpps).

Possibly with a larger hash-map, there will be LLC misses worsening the
situation.

### Note 2

When we did not steered the flows, the importance of RSS becomes visible.
In this case surprisingly the 5000 case performed better, guessing the RSS did
a better job in that case.

100-flows: 17.0 Mpps
5000-flows: 17.5 Mpps
