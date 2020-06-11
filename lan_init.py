#
# foris-controller
# Copyright (C) 2019 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#

import typing
import logging
import ipaddress

from foris_controller.exceptions import UciException
from foris_controller_backends.services import OpenwrtServices
from foris_controller_backends.uci import (
    UciBackend,
    get_option_named,
    parse_bool,
    store_bool,
    get_sections_by_type,
)

from foris_controller_backends.files import BaseFile, path_exists

from foris_controller_backends.maintain import MaintainCommands

logger = logging.getLogger(__name__)


class LanFiles(BaseFile):
    DNSMASQ_LEASE_FILE = "/tmp/dhcp.leases"
    CONNTRACK_FILE = "/proc/net/nf_conntrack"

    def get_dhcp_clients(self, network, netmask):
        if not path_exists(LanFiles.DNSMASQ_LEASE_FILE):
            return []
        lines = self._file_content(LanFiles.DNSMASQ_LEASE_FILE).strip("\n \t").split("\n")
        # conntrack = self._file_content(LanFiles.CONNTRACK_FILE)
        res = []
        for line in lines:
            try:
                timestamp, mac, ip, hostname, _ = line.split(" ")
                timestamp = int(timestamp)
            except ValueError:
                continue

            # filter by network and netmask
            if ipaddress.ip_address(ip) in ipaddress.ip_network(
                f"{network}/{netmask}", strict=False
            ):
                res.append(
                    {
                        "expires": timestamp,
                        "mac": mac.upper().strip(),
                        "ip": ip,
                        "hostname": hostname,
                        "active": True,
                    }
                )

        return res


class LanUci(object):
    DEFAULT_DHCP_START = 100
    DEFAULT_DHCP_LIMIT = 150
    DEFAULT_LEASE_TIME = 12 * 60 * 60
    DEFAULT_ROUTER_IP = "192.168.1.1"
    DEFAULT_NETMASK = "255.255.255.0"

    def get_client_list(self, uci_data, network, netmask):
        file_records = LanFiles().get_dhcp_clients(network, netmask)
        uci_data = get_sections_by_type(uci_data, "dhcp", "host")

        for record in uci_data:
            if "mac" in record["data"]:
                record["data"]["mac"] = record["data"]["mac"].strip().upper()

        uci_map = {
            e["data"]["mac"]: e["data"]
            for e in uci_data
            if "mac" in e["data"]
            and len(e["data"]["mac"].split(" ")) == 1  # ignore multi mac records
            and "ip" in e["data"]
            and (
                e["data"]["ip"] == "ignore"
                or self.in_network(e["data"]["ip"], network, netmask)  # has to be in lan
            )
        }
        for record in file_records:
            if record["mac"] in uci_map:
                # override actual ip by the one which is supposed to be set
                record["ip"] = uci_map[record["mac"]]["ip"]
                hostname = uci_map[record["mac"]].get("name", "")
                record["hostname"] = hostname if hostname else record["hostname"]
                del uci_map[record["mac"]]
        for record in uci_map.values():
            file_records.append(
                {
                    "ip": record["ip"],
                    "hostname": record.get("name", ""),
                    "mac": record["mac"],
                    "active": False,
                    "expires": 0,
                }
            )
        return file_records

    @staticmethod
    def _normalize_lease(value):
        leasetime = str(value)
        if leasetime == "infinite":
            return 0
        elif leasetime.endswith("m"):
            return int(leasetime[:-1]) * 60
        elif leasetime.endswith("h"):
            return int(leasetime[:-1]) * 60 * 60
        elif leasetime.endswith("d"):
            return int(leasetime[:-1]) * 60 * 60 * 24
        else:
            return int(leasetime)

    def get_settings(self):

        with UciBackend() as backend:
            network_data = backend.read("network")
            dhcp_data = backend.read("dhcp")
            try:
                wireless_data = backend.read("wireless")
            except UciException:
                wireless_data = {}

        mode = get_option_named(network_data, "network", "lan", "_turris_mode", "managed")

        mode_managed = {"dhcp": {}}
        mode_managed["router_ip"] = get_option_named(
            network_data, "network", "lan", "ipaddr", LanUci.DEFAULT_ROUTER_IP
        )
        mode_managed["netmask"] = get_option_named(
            network_data, "network", "lan", "netmask", LanUci.DEFAULT_NETMASK
        )
        mode_managed["dhcp"]["enabled"] = not parse_bool(
            get_option_named(dhcp_data, "dhcp", "lan", "ignore", "0")
        )
        mode_managed["dhcp"]["start"] = int(
            get_option_named(dhcp_data, "dhcp", "lan", "start", self.DEFAULT_DHCP_START)
        )
        mode_managed["dhcp"]["limit"] = int(
            get_option_named(dhcp_data, "dhcp", "lan", "limit", self.DEFAULT_DHCP_LIMIT)
        )
        mode_managed["dhcp"]["lease_time"] = LanUci._normalize_lease(
            get_option_named(dhcp_data, "dhcp", "lan", "leasetime", self.DEFAULT_LEASE_TIME)
        )
        if mode_managed["dhcp"]["enabled"]:
            mode_managed["dhcp"]["clients"] = self.get_client_list(
                dhcp_data, mode_managed["router_ip"], mode_managed["netmask"]
            )
        else:
            mode_managed["dhcp"]["clients"] = []

        mode_unmanaged = {}
        mode_unmanaged["lan_type"] = get_option_named(network_data, "network", "lan", "proto")
        hostname = get_option_named(network_data, "network", "lan", "hostname", "")
        mode_unmanaged["lan_dhcp"] = {"hostname": hostname} if hostname else {}
        mode_unmanaged["lan_static"] = {
            "ip": get_option_named(
                network_data, "network", "lan", "ipaddr", LanUci.DEFAULT_ROUTER_IP
            ),
            "netmask": get_option_named(
                network_data, "network", "lan", "netmask", LanUci.DEFAULT_NETMASK
            ),
            "gateway": get_option_named(
                network_data,
                "network",
                "lan",
                "gateway",
                get_option_named(
                    network_data, "network", "lan", "ipaddr", LanUci.DEFAULT_ROUTER_IP
                ),
            ),
        }
        dns = get_option_named(network_data, "network", "lan", "dns", [])
        dns = dns if isinstance(dns, (list, tuple)) else [e for e in dns.split(" ") if e]
        dns = reversed(dns)  # dns with higher priority should be added last
        try:
            # use ipv4 addresses only
            dns = [e for e in dns if isinstance(ipaddress.ip_address(e), ipaddress.IPv4Address)]
        except ValueError:
            dns = []
        mode_unmanaged["lan_static"].update(zip(("dns1", "dns2"), dns))

        from foris_controller_backends.networks import NetworksUci

        return {
            "mode": mode,
            "mode_managed": mode_managed,
            "mode_unmanaged": mode_unmanaged,
            "interface_count": NetworksUci.get_interface_count(network_data, wireless_data, "lan"),
            "interface_up_count": NetworksUci.get_interface_count(
                network_data, wireless_data, "lan", True
            ),
        }

    def filter_dhcp_client_records(
        self,
        backend: UciBackend,
        dhcp_data,
        old_router_ip: typing.Optional[str],
        old_netmask: typing.Optional[str],
        new_router_ip: str,
        new_netmask: str,
        new_start: int,
        new_limit: int,
    ):
        for record in get_sections_by_type(dhcp_data, "dhcp", "host"):
            if "ip" in record["data"] and record["data"]["ip"] != "ignore":
                # remove if in dynamic range
                if self.in_range(record["data"]["ip"], new_router_ip, new_start, new_limit):
                    backend.del_section("dhcp", record["name"])

                # remove if it was in old network and is not in the new
                if old_router_ip and old_netmask:
                    if self.in_network(
                        record["data"]["ip"], old_router_ip, old_netmask
                    ) and not self.in_network(record["data"]["ip"], new_router_ip, new_netmask):
                        backend.del_section("dhcp", record["name"])

    def update_settings(self, mode, mode_managed=None, mode_unmanaged=None):
        """  Updates the lan settings in uci

        :param mode: lan setting mode managed/unmanaged
        :type mode: str
        :param mode_managed: managed mode settings {"router_ip": ..., "netmask":..., "dhcp": ...}
        :type mode_managed: dict
        :param mode_unmanaged: {"lan_type": "none/dhcp/static", "lan_static": {}, ...}
        :type mode_unmanaged: dict
        """

        with UciBackend() as backend:

            backend.add_section("network", "interface", "lan")
            backend.set_option("network", "lan", "_turris_mode", mode)

            if mode == "managed":
                network_data = backend.read("network")
                dhcp_data = backend.read("dhcp")
                backend.set_option("network", "lan", "proto", "static")
                backend.set_option("network", "lan", "ipaddr", mode_managed["router_ip"])
                backend.set_option("network", "lan", "netmask", mode_managed["netmask"])

                backend.add_section("dhcp", "dhcp", "lan")
                dhcp = mode_managed["dhcp"]
                backend.set_option("dhcp", "lan", "ignore", store_bool(not dhcp["enabled"]))

                # set dhcp part (this device acts as a server here)
                if dhcp["enabled"]:
                    backend.set_option("dhcp", "lan", "start", dhcp["start"])
                    backend.set_option("dhcp", "lan", "limit", dhcp["limit"])
                    backend.set_option(
                        "dhcp",
                        "lan",
                        "leasetime",
                        "infinite" if dhcp["lease_time"] == 0 else dhcp["lease_time"],
                    )

                    # this will override all user dhcp options
                    # TODO we might want to preserve some options
                    backend.replace_list(
                        "dhcp", "lan", "dhcp_option", ["6,%s" % mode_managed["router_ip"]]
                    )

                    # update dhcp records when changing lan ip+network or start+limit
                    # get old network
                    old_router_ip = get_option_named(network_data, "network", "lan", "ipaddr", "")
                    old_netmask = get_option_named(network_data, "network", "lan", "netmask", "")
                    self.filter_dhcp_client_records(
                        backend,
                        dhcp_data,
                        old_router_ip,
                        old_netmask,
                        mode_managed["router_ip"],
                        mode_managed["netmask"],
                        dhcp["start"],
                        dhcp["limit"],
                    )

            elif mode == "unmanaged":
                backend.set_option("network", "lan", "proto", mode_unmanaged["lan_type"])
                # disable dhcp you are not managing this network...
                backend.add_section("dhcp", "dhcp", "lan")
                backend.set_option("dhcp", "lan", "ignore", store_bool(True))
                if mode_unmanaged["lan_type"] == "dhcp":
                    if "hostname" in mode_unmanaged["lan_dhcp"]:
                        backend.set_option(
                            "network", "lan", "hostname", mode_unmanaged["lan_dhcp"]["hostname"]
                        )

                elif mode_unmanaged["lan_type"] == "static":
                    backend.set_option(
                        "network", "lan", "ipaddr", mode_unmanaged["lan_static"]["ip"]
                    )
                    backend.set_option(
                        "network", "lan", "netmask", mode_unmanaged["lan_static"]["netmask"]
                    )
                    backend.set_option(
                        "network", "lan", "gateway", mode_unmanaged["lan_static"]["gateway"]
                    )
                    dns = [
                        mode_unmanaged["lan_static"][name]
                        for name in ("dns2", "dns1")
                        if name in mode_unmanaged["lan_static"]
                    ]  # dns with higher priority should be added last
                    backend.replace_list("network", "lan", "dns", dns)
                elif mode_unmanaged["lan_type"] == "none":
                    pass  # no need to handle

        # update wizard passed in foris web (best effort)
        try:
            from foris_controller_backends.web import WebUciCommands

            WebUciCommands.update_passed("lan")
        except UciException:
            pass

        MaintainCommands().restart_network()

        return True

    @staticmethod
    def in_range(ip: str, start_ip: str, start: int, limit: int) -> bool:
        """ Determine whether ip is in range defined by (start_ip + start .. start_ip + start, + limit)
        :param ip: ip to be compared
        :param start_ip: ip for where is range calculated
        :param start: start offset
        :param limit: count of ips
        :return: True if ip is in range False otherwise
        """
        dynamic_first = ipaddress.ip_address(start_ip) + start
        dynamic_last = dynamic_first + limit
        return dynamic_first <= ipaddress.ip_address(ip) <= dynamic_last

    @staticmethod
    def in_network(ip: str, ip_root: str, netmask: str) -> bool:
        """ Determine whether ip is in range defined by (start_ip + start .. start_ip + start, + limit)
        :param ip: ip to be compared
        :param start_ip: ip for where is range calculated
        :param start: start offset
        :param limit: count of ips
        :return: True if ip is in range False otherwise
        """
        network = ipaddress.ip_network(f"{ip_root}/{netmask}", strict=False)
        return ipaddress.ip_address(ip) in network

    def set_dhcp_client(self, ip: str, mac: str, hostname: str) -> typing.Optional[str]:
        """ Creates / updates a configuration of a single dhcp client
        :param ip: ip address to be assigned (or 'ignore' - don't assign any ip)
        :param mac: mac address of the client
        :param hostname: hostname of the client (can be empty)
        :returns: None if update passes error string otherwise
        """
        mac = mac.upper()

        with UciBackend() as backend:
            dhcp_data = backend.read("dhcp")
            network_data = backend.read("network")

            router_ip = get_option_named(
                network_data, "network", "lan", "ipaddr", LanUci.DEFAULT_ROUTER_IP
            )
            netmask = get_option_named(
                network_data, "network", "lan", "netmask", LanUci.DEFAULT_NETMASK
            )
            start = int(
                get_option_named(dhcp_data, "dhcp", "lan", "start", LanUci.DEFAULT_DHCP_START)
            )
            limit = int(
                get_option_named(dhcp_data, "dhcp", "lan", "limit", LanUci.DEFAULT_DHCP_LIMIT)
            )

            if ip != "ignore":  # ignore means that dhcp server won't provide ip for givem macaddr
                if LanUci.in_range(ip, router_ip, start, limit):
                    return "in-dynamic"

                if not LanUci.in_network(ip, router_ip, netmask):
                    return "out-of-network"

                mode = get_option_named(network_data, "network", "lan", "_turris_mode", "managed")
                if mode != "managed":
                    return "disabled"

                dhcp_enabled = not parse_bool(
                    get_option_named(dhcp_data, "dhcp", "lan", "ignore", "0")
                )
                if not dhcp_enabled:
                    return "disabled"

            section_name = None
            for section in get_sections_by_type(dhcp_data, "dhcp", "host"):
                if "mac" not in section["data"]:
                    continue
                macs = [e.upper() for e in section["data"]["mac"].split(" ")]
                if mac in macs:
                    if len(macs) == 1:
                        section_name = section["name"]
                        break
                    else:
                        # Split record => remove mac
                        backend.set_option(
                            "dhcp", section["name"], "mac", " ".join([e for e in macs if e != mac])
                        )
                        break

            if section_name is None:
                # section was not found or the record was splitted
                section_name = backend.add_section("dhcp", "host")

            backend.set_option("dhcp", section_name, "mac", mac)
            backend.set_option("dhcp", section_name, "ip", ip)
            backend.set_option("dhcp", section_name, "name", hostname)

        with OpenwrtServices() as services:
            services.restart("dnsmasq")

        return None  # everyting went ok
