# DOCA Flow Hairpin Queue Mesh Example

Demonstrates how to create a many-to-many mapping of PFs, VFs, and/or SFs using
DOCA Flow and DPDK hairpin queues.

## Host Environment Setup

Create the VFs on the host.
If the BF is in DPU mode, additional steps are needed to enable trust. See below.

```
# Create SFs
# Replace enp23s0f0 with your device
echo 2 > /sys/class/net/enp23s0f0np0/device/sriov_numvfs
echo 2 > /sys/class/net/enp23s0f1np1/device/sriov_numvfs
```

## Configuring and Building
If necessary, set the `PKG_CONFIG_PATH`.
```
export PKG_CONFIG_PATH=/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/grpc/lib/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig
```

Use `meseon` and `ninja` to configure and build.
```
meson build
ninja -C build
```

## Testing
Run the example program

Replace 17:00.0 with your device's BDF
```
build/doca-hairpin-mesh-ex -a17:00.0,dv_flow_en=2 -a17:00.3,dv_flow_en=2 -a17:00.4,dv_flow_en=2 -a17:00.1,dv_flow_en -a17:02.3,dv_flow_en=2 -a17:02.4,dv_flow_en -c0x7f
```
Sample output:
```
EAL: Detected CPU lcores: 64
EAL: Detected NUMA nodes: 2
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
...
[22:20:47:312497][DOCA][INF][HAIRPIN_MESH_EX:566]: Initialized HairpinMeshExample with 7 cores, 4 ports
[22:20:47:474738][DOCA][INF][NUTILS:515]: rte_eth_tx_hairpin_queue_setup(0, 6) -> {0, 6}
[22:20:47:474792][DOCA][INF][NUTILS:524]: rte_eth_rx_hairpin_queue_setup(0, 6) -> {0, 6}
[22:20:47:474798][DOCA][INF][NUTILS:515]: rte_eth_tx_hairpin_queue_setup(0, 7) -> {1, 6}
[22:20:47:474802][DOCA][INF][NUTILS:524]: rte_eth_rx_hairpin_queue_setup(0, 7) -> {1, 6}
[22:20:47:474806][DOCA][INF][NUTILS:515]: rte_eth_tx_hairpin_queue_setup(0, 8) -> {2, 6}
[22:20:47:474810][DOCA][INF][NUTILS:524]: rte_eth_rx_hairpin_queue_setup(0, 8) -> {2, 6}
[22:20:47:474815][DOCA][INF][NUTILS:515]: rte_eth_tx_hairpin_queue_setup(0, 9) -> {3, 6}
[22:20:47:474819][DOCA][INF][NUTILS:524]: rte_eth_rx_hairpin_queue_setup(0, 9) -> {3, 6}
[22:20:47:474823][DOCA][INF][NUTILS:532]: Port 0: Configured hairpin mesh queues [6..9] to ports [0..3]
...
[22:20:51:211269][DOCA][INF][dpdk_id_pool:69]: Initialized ID Pool tm_12 with address 0x55ace5f52640 of size 8192, min index 0
[22:20:51:211450][DOCA][INF][dpdk_pipe_common:471]: entry pool 7 cache enabled, change nb_entries from 8192 to 11264
```
Use `CTRL-C` to exit.

## Enabling Trust (DPU Mode only)

On the Host, create the VFs as shown above. Then perform the following steps.

Host:
```
/etc/init.d/openibd stop
```
DPU:
```
devlink dev eswitch set pci/0000:03:00.0 mode legacy
devlink dev eswitch set pci/0000:03:00.1 mode legacy

echo "none" > "/sys/class/net/p0/compat/devlink/encap"
echo "none" > "/sys/class/net/p1/compat/devlink/encap"

devlink dev eswitch set pci/0000:03:00.0 mode switchdev
devlink dev eswitch set pci/0000:03:00.1 mode switchdev

mlxreg -d /dev/mst/mt41686_pciconf0 --reg_name VHCA_TRUST_LEVEL --yes --indexes "vhca_id=0x0,all_vhca=0x1" --set "trust_level=0x1"

mlxreg -d /dev/mst/mt41686_pciconf0.1 --reg_name VHCA_TRUST_LEVEL --yes --indexes "vhca_id=0x0,all_vhca=0x1" --set "trust_level=0x1"
```
Host:
```
/etc/init.d/openibd start
```