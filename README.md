## qemu_turrisos
Run TurrisOS inside QEMU

# Quick How-to
```
   git clone https://github.com/jose1711/qemu_turrisos.git
   cd qemu_turrisos
   wget --output-document=zImage https://downloads.openwrt.org/snapshots/targets/armvirt/32/openwrt-armvirt-32-zImage
   mkdir root && cd root

   Turris OS3:
     wget --output-document=- https://repo.turris.cz/archive/omnia/3.2.1/omnia-medkit-201610271801.tar.gz | tar xvzf -

   Turris OS4:
     wget --output-document=- https://repo.turris.cz/archive/4.0.6/medkit/omnia-medkit-latest.tar.gz | tar xvzf -

   Turris OS5 (latest)
     wget --output-document=- https://repo.turris.cz/hbs/medkit/omnia-medkit-latest.tar.gz | tar xvzf -

   cd ..
   sudo ./start_omnia.sh
   configure using wizard in browser: https://192.168.1.1
```

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
