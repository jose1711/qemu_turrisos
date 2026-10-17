# QEMU shim for turrishw (TOS 6+)
#
# turrishw detects network ports by device paths of the real hardware,
# virtio NICs of QEMU's virt machine are not recognized at all. This file
# shadows turrishw/turrishw.pyc, loads the original module and when running
# inside QEMU pretends to be an Omnia with NICs mapped to its ports
# (see start_omnia.sh for the order of NICs).
import importlib.util
import os
import types

from . import utils

QEMU_MODEL = "linux,dummy-virt"
PORTS = {"eth0": "LAN0", "eth1": "WAN", "eth2": "LAN1"}

_spec = importlib.util.spec_from_file_location(
    __package__ + "._orig", os.path.join(os.path.dirname(__file__), "turrishw.pyc")
)
_orig = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_orig)


def _is_qemu():
    try:
        model = utils.get_first_line(utils.inject_file_root("sys/firmware/devicetree/base/model"))
    except OSError:
        return False
    return model.rstrip("\x00") == QEMU_MODEL


def _qemu_interfaces():
    ifaces = []
    for name, label in PORTS.items():
        path = utils.inject_file_root("sys/class/net", name)
        if not os.path.exists(path):
            continue
        macaddr = utils.get_first_line(os.path.join(path, "address")).strip()
        iface = utils.make_iface(name, "eth", "eth", label, macaddr)
        if iface:
            # virtio NICs are PCI devices, real Omnia ports are not and
            # foris-controller schema rejects vendor/pci_id for eth ports
            iface.vendor = None
            iface.pci_id = None
            ifaces.append(iface)
    return ifaces


if _is_qemu():
    _orig.get_model = lambda: "OMNIA"
    _orig.omnia = types.SimpleNamespace(get_interfaces=_qemu_interfaces)

get_model = _orig.get_model
get_ifaces = _orig.get_ifaces
