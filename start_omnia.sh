#!/bin/sh
# start Turris Omnia inside QEMU
#
# network config (TOS3):
#   eth0 -> br-lan (192.168.1.1/24 - static, factory default), communicates with host system over ledetap0
#   eth1 -> wan    (10.x.x.x/24 - dhcp - IP assigned by QEMU)
#   eth2 -> unused (normally inside br-lan together with eth0 and wlan cards)
#
# how to use:
#   git clone ..
#   cd turris_qemu
#   curl -o zImage https://downloads.openwrt.org/snapshots/targets/armvirt/32/openwrt-armvirt-32-zImage
#   mkdir root && cd root
#
#   Turris OS3:
#     wget --output-document=- https://repo.turris.cz/archive/omnia/3.2.1/omnia-medkit-201610271801.tar.gz | tar xvzf -
#
#   Turris OS4:
#     wget --output-document=- https://repo.turris.cz/archive/4.0.6/medkit/omnia-medkit-latest.tar.gz | tar xvzf -
#
#   Turris OS5 (latest)
#     wget --output-document=- https://repo.turris.cz/hbs/medkit/omnia-medkit-latest.tar.gz | tar xvzf -
#
#   cd ..
#   sudo ./start_omnia.sh
#   configure using wizard in browser: https://192.168.1.1
#     

LANG=C
LAN1=ledetap0
LAN2=ledetap1
KERNEL=zImage
MEM=620

# by default Omnia is accessible on 192.168.1.1
# let's make sure this IP is not local to our network
ip r get 192.168.1.1 | grep -q via
if [ $? -ne 0 ]
then
  echo "Default Omnia's IP (192.168.1.1) is already part of your network, sorry.."
  exit 1
fi

cd $(dirname $0)

# enable ip forwarding
fwd_orig=$(sysctl net.ipv4.ip_forward | awk '{print $NF}')
sysctl net.ipv4.ip_forward=1

# create tap interfaces which will be connected to Omnia's LAN NIC
ip tuntap add mode tap $LAN1
ip link set dev $LAN1 up
ip tuntap add mode tap $LAN2
ip link set dev $LAN2 up

# configure interface with static ip to avoid overlapping routes                         
ip addr add 192.168.1.2/24 dev $LAN1

# allow iptables to pass packets from/to tunnel
iptables -I OUTPUT -o ledetap0 -j ACCEPT
iptables -I FORWARD -i ledetap0 -j ACCEPT
iptables -I INPUT -i ledetap0 -j ACCEPT

# try to convince the system it's running on the real Omnia
./provision_rootfs.sh

qemu-system-arm \
   -nographic -M virt -kernel "${KERNEL}" -m "${MEM}" -no-reboot \
   -fsdev local,id=rootdev,path=root,security_model=none \
   -device virtio-9p-pci,fsdev=rootdev,mount_tag=/dev/root \
   -append 'rootflags=trans=virtio,version=9p2000.L,cache=loose rootfstype=9p' \
   -device virtio-net-pci,netdev=lan \
   -netdev tap,id=lan,ifname=$LAN1,script=no,downscript=no \
   -device virtio-net-pci,netdev=wan \
   -netdev user,id=wan \
   -device virtio-net-pci,netdev=lan2 \
   -netdev tap,id=lan2,ifname=$LAN2,script=no,downscript=no \

# cleanup. delete tap interface created earlier
ip addr flush dev $LAN1
ip link set dev $LAN1 down
ip tuntap del mode tap dev $LAN1

ip addr flush dev $LAN2
ip link set dev $LAN2 down
ip tuntap del mode tap dev $LAN2

sysctl net.ipv4.ip_forward=${fwd_orig}

# remove fw rules
iptables -D OUTPUT -o ledetap0 -j ACCEPT
iptables -D FORWARD -i ledetap0 -j ACCEPT
iptables -D INPUT -i ledetap0 -j ACCEPT
