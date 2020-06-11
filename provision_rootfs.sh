#!/bin/bash
# provision rootfs of Turris OS running
# inside QEMU

LANG=C

echo "Checking/fixing ttyAMA0 in inittab.."
grep -q ^ttyAMA0 root/etc/inittab
if [ $? -ne 0 ]
then
  echo 'ttyAMA0::askfirst:/bin/ash --login' >> root/etc/inittab
fi

echo "Replacing crypto-wrapper.."
cat > root/usr/bin/crypto-wrapper <<HERE
#!/bin/sh
echo 0000000000000000
exit
HERE

echo "Checking/adding /tmp/sysinfo/model (and dhcp client).."
grep -q tmp/sysinfo/model root/etc/init.d/start-indicator
if [ $? -ne 0 ]
then
  sed -i '/msg=/a\
        echo "Turris Omnia" > \/tmp\/sysinfo\/model \
        # Wan is configured with DHCP \
        # \/sbin\/udhcpc -i eth1' root/etc/init.d/start-indicator
fi

echo "Faking iw.."
file root/usr/sbin/iw | grep -q 'script'
if [ $? -ne 0 ]
then
  mv root/usr/sbin/iw root/usr/sbin/iw.orig
  cat >root/usr/sbin/iw <<HereDoc
#!/bin/sh
cat <<HERE
phy#1
        Interface wlan1
                ifindex 16
                wdev 0x100000002
                addr ff:ff:ff:ff:ff:ff
                ssid WIFI1
                type AP
                channel 9 (2452 MHz), width: 20 MHz, center1: 2452 MHz
phy#0
        Interface wlan0
                ifindex 15
                wdev 0x2
                addr ff:ff:ff:ff:ff:ff
                ssid WIFI2
                type AP
                channel 36 (5180 MHz), width: 40 MHz, center1: 5190 MHz
HERE
HereDoc

chmod +x root/usr/sbin/iw
fi

#echo "Writing resolv.conf.."
#cat > root/etc/resolv.conf <<HERE
#search lan
#nameserver 8.8.8.8
#HERE

echo "Patching utils.py.."
# this unbreaks TOS4 guided mode
cp turrishw_utils.py root/usr/lib/python3.6/site-packages/turrishw/utils.py

echo "Patching lan/__init__.py"
cp lan_init.py root/usr/lib/python3.6/site-packages/foris_controller_backends/lan/__init__.py
