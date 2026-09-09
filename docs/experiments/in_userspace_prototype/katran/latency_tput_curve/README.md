# About

This directory holds the result of experiments comparing base-line Katran
implementation against a version of it using 3-phase lookup for improving the
hash-map cache efficiency.
The experiments measuring the latency vs. offered load curve.

Different load-balancing algrithms of Katran was considered:
1. consistent hashing: UDP packets with different source addresses but going to
   the same destination (VIP) where generated toward Katran. Katran applies a
   consistent hashing (Maglev like) load balancing and stores the decision.
   This experiment excersices lookup into the Hash map that stores the
   state.
2. Server id based routing: Katran allows TCP (also QUIC) to provide a
   server-id header option and use it for routing. The experiment execersices
   lookup into to the array storing the server-id mapping to real server
   address.

In each sub-directory, the data is organized as follows.Let `X` be the number
of active flows. Directory named `X`\_flows will hold data of the experiment.
Inside each directory there will be a `base_line` and `3phase` directory
further separating the data of each measurment.

