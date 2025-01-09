# About

This directory holds the result of experiments comparing base-line katran
implementation against a version of it using 3-phase lookup for improving the
hash-map cache efficiency.
The experiments measuring the latency vs. offered load curve.

The data is organized as follows.Let `X` be the number of active flows.
directory named `X`\_flows will hold data of the experiment.
Inside each directory there will be a `base_line` and `3phase` directory
further separating the data of each measurment.

