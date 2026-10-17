#!/bin/sh
# container entrypoint: make VM's ssh, http and https reachable
# via container ports, then start the VM
python3 port_forward.py 192.168.1.1 22 80 443 &
exec ./start_omnia.sh
