# How to use


**setup:**
```
[ Machine running Katran] <--> [Machine generating traffic]
```

1. Set the `DEFAULT_MAC` in the script to the MAC address of traffic generator.

**workload genetor command example:**

> remember to enable add_katran_opt flag command line args if doing with TCP header option

```
sudo ./build/client_tcp_timestamp -a $NET_PCI --lcores 0@(2,4) -- --client --ip-local 192.168.1.2 --ip-dest 10.10.0.1 --duration 300 --rate 5000000 --zipf-client-addr 1/1/0
```

