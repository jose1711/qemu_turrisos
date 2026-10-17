#!/usr/bin/env python3
# forward TCP ports to the VM, used inside the container so that
# its ports can be published (rootless podman delivers published
# ports via loopback where iptables DNAT doesn't apply)
#
# usage: port_forward.py HOST PORT [PORT..]

import socket
import sys
import threading


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        src.close()
        dst.close()


def forward(host, port):
    server = socket.create_server(("0.0.0.0", port), reuse_port=True)
    while True:
        client, _ = server.accept()
        try:
            upstream = socket.create_connection((host, port))
        except OSError:
            # VM is not up (yet)
            client.close()
            continue
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: {} HOST PORT [PORT..]".format(sys.argv[0]))
    for port in sys.argv[3:]:
        threading.Thread(target=forward, args=(sys.argv[1], int(port)), daemon=True).start()
    forward(sys.argv[1], int(sys.argv[2]))
