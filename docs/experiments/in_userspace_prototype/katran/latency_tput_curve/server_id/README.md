# Description

In this experiment I show the importance of using prefetch instructions inside
the eBPF programs. Katran load balancer is studied under a TCP workload
(64 B of payload size) carrying a server-id header option. The server-id is
selected randomly (using a LGC random number generator [why?]). This will cause
memory access to an array map, which we show prefetching its elements improve
the performance.

In order to handle higher loads, two instances of Katran (using Servant to run
it in user-space) is run on cores 2 and 4 of a XL170 machine from Cloudlab Utah
cluster. This will also increase the pressure on the LLC since it is shared
across cores.

Under the above deployment configuration, I noticed that the IP-in-IP
encapsulation performed before forwarding each packet also cause cache
misses (I am not sure if it is the case when only one core is involved). I also
show that prefetching it would improve the performance.

The latency vs. throughput curve was measured by generating load from one
machine and then using a seperate machine for measuring the latency. The load
is evenly distributed among each core of the server by sending traffics from
two different source ports (1201, 1201). On the server machine there is a rule
that maps each source port to one instance of the server.

The experiment are done in four scenarios. The baseline is the original
version of the katran. Then the effect of array prefteching and headroom
prefetching are evaluated seperately. In the last case both optimizations are
used.
