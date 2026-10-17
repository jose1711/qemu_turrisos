## qemu_turrisos
Run TurrisOS inside QEMU

# Quick How-to
```
   git clone https://github.com/jose1711/qemu_turrisos.git
   cd qemu_turrisos
   wget --output-document=zImage https://downloads.openwrt.org/snapshots/targets/armsr/armv7/openwrt-armsr-armv7-generic-kernel.bin
   mkdir root && cd root

   Turris OS3:
     wget --output-document=- https://repo.turris.cz/archive/omnia/3.2.1/omnia-medkit-201610271801.tar.gz | sudo tar xvzf -

   Turris OS4:
     wget --output-document=- https://repo.turris.cz/archive/4.0.6/medkit/omnia-medkit-latest.tar.gz | sudo tar xvzf -

   Turris OS (latest)
     wget --output-document=- https://repo.turris.cz/hbs/medkit/medkit-omnia-latest.tar.gz | sudo tar xvzf -

   cd ..
   sudo ./start_omnia.sh
   configure using wizard in browser: https://192.168.1.1
```

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
