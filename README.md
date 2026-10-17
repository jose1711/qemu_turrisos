## qemu_turrisos
Run TurrisOS inside QEMU

# Quick How-to
```
   git clone --depth 1 https://github.com/jose1711/qemu_turrisos.git
   cd qemu_turrisos
   ./fetch.sh            # latest Turris OS, or e.g. ./fetch.sh 3.11.23
   sudo ./start_omnia.sh
   configure using wizard in browser: https://192.168.1.1
```

`fetch.sh` downloads the OpenWrt kernel and Turris OS medkit (any version from
https://repo.turris.cz/archive/), verifies their signatures against keys in
`keys/` and extracts the medkit into `root/`. Signatures are checked with
`signify`/`usign` or, when not installed, with python3 `cryptography` module.
Old releases (e.g. 3.2.1) are not signed and require `--no-verify`.

Alternatively run it in a container (VM console only, web UI is reachable
from inside the container at https://192.168.1.1):

```
podman build -t turrisos .            # or --build-arg VERSION=5.0.3
podman run --rm -ti --init --cap-add=NET_ADMIN --device=/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 turrisos
```

Required commands: `wget`, `tar`, `sha256sum`, `qemu-system-arm`, `ip`,
`iptables`, `sysctl`, `file`.

Network ports inside the VM: `eth0` = LAN0, `eth1` = WAN (QEMU user network, DHCP), `eth2` = LAN1.

Tested with Turris OS 9.1.3 and OpenWrt armsr kernel 6.18: guide in router mode,
WAN, DNS and updater work. `provision_rootfs.sh` installs a `turrishw` shim
(`turrishw_qemu.py`) so that virtio NICs are recognized and adds WAN network
config on first boot (`qemu_network.uci-defaults`).

## Known issues

### WAN connection is not detected in TOS3

Add `ifname 'eth1` into `/etc/config/network`, then reboot.

```
config interface 'wan'
        option proto 'dhcp'
        option ifname 'eth1'
```

### Guided mode may fail in TOS4

Resolution:
skip it and configure network manually

### Foris reports `Remote Exception: Internal error Failed to obtain network info('<class 'foris_controller.exceptions.GenericError'>')`

Edit `/etc/config/network` specifying `wan` interface:

```
config interface 'wan'
        option ifname 'eth1'
        option proto 'dhcp'
        option ip6assign '60'
        option dns '8.8.8.8 8.8.4.4'
```
reboot and then verify by running `ifstatus wan`
