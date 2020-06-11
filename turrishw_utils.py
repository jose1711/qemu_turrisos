# Copyright (c) 2018, CZ.NIC, z.s.p.o. (http://www.nic.cz/)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the CZ.NIC nor the
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL CZ.NIC BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import os


def get_first_line(filename):
    if filename == '/sys/firmware/devicetree/base/model':
        return 'Turris Omnia'
    with open(filename, 'r') as f:
        return f.readline()


def get_iface_state(iface):
    from turrishw import __P_ROOT__
    operstate = get_first_line(os.path.join(__P_ROOT__, 'sys/class/net/{}/operstate'.format(iface)))
    if operstate.strip() == "up":
        return "up"
    else:
        return "down"


def get_iface_speed(iface):
    from turrishw import __P_ROOT__
    try:
        speed = get_first_line(os.path.join(__P_ROOT__, 'sys/class/net/{}/speed'.format(iface)))
        return int(speed)
    except (OSError, ValueError):
        # can't read the file or can't convert value to int (file is empty)
        return 0


def find_iface_type(iface):
    from turrishw import __P_ROOT__
    path = os.path.join(__P_ROOT__, 'sys/class/net', iface)
    if os.path.isdir(os.path.join(path, "phy80211")):
        return "wifi"
    if os.path.isdir(os.path.join(path, "qmi")):
        return "wwan"
    # TODO: support other protocols of LTE modems
    return "eth"


def get_ifaces():
    from turrishw import __P_ROOT__
    path = os.path.join(__P_ROOT__, 'sys/class/net')
    for f in os.listdir(path):
        yield f


def get_TOS_major_version():
    from turrishw import __P_ROOT__
    version = get_first_line(os.path.join(__P_ROOT__, 'etc/turris-version'))
    parts = version.split('.')
    return int(parts[0])


def iface_info(iface, type, bus, module_id, slot, macaddr):
    state = get_iface_state(iface)
    return {"name": iface, "type": type, "bus": bus, "state": state,
            "slot": slot, "module_id": module_id, 'macaddr': macaddr,
            "link_speed": get_iface_speed(iface) if state == "up" else 0}


def ifaces_array2dict(ifaces_array):
    d = {}
    for iface in ifaces_array:
        name = iface["name"]
        d[name] = {i:iface[i] for i in iface if i!='name'}
    return d

