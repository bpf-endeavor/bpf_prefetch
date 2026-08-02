# Artifact Reproducibility Guide

## Hardware 

Hardware: the experiments were performed on [Cloudlab](https://www.cloudlab.us/) platform using machines from [Utah cluster with type c6525-25g](https://www.utah.cloudlab.us/portal/show-nodetype.php?type=c6525-25g).

We used two directly connected servers for each experiment: one served as the
load generator while the other ran the Beeswax program (Figure 1).

![For the experiments to servers are connected directly](./docs/repository/back_to_back_setup.jpg)

Each server is equipped with an AMD EPYC 7302P 16-Core (Zen 2 – Rome) processor
with 0.5 MB of L1, 8 MB of L2, and 128 MB of LLC; has 128 GB of memory; and a
Mellanox Connect-X5 (MT27800 Family) NICs.

> TODO: make the repository a cloudlab profile
