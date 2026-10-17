# build (latest Turris OS or a specific version):
#   podman build -t turrisos .
#   podman build -t turrisos --build-arg VERSION=5.0.3 .
# run:
#   podman run --rm -ti --init --cap-add=NET_ADMIN --device=/dev/net/tun \
#     --sysctl net.ipv4.ip_forward=1 turrisos
# (works with docker as well)

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
      ca-certificates wget file iproute2 iptables procps \
      qemu-system-arm ipxe-qemu python3-cryptography && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /qemu_turrisos
COPY . .

ARG VERSION=latest
RUN ./fetch.sh $VERSION

ENTRYPOINT ["./start_omnia.sh"]
