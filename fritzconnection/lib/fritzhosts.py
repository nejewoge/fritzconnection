"""
Module to access and control the known hosts.
"""
# This module is part of the FritzConnection package.
# https://github.com/kbr/fritzconnection
# License: MIT (https://opensource.org/licenses/MIT)
# Author: Klaus Bremer


import itertools
from ..core.exceptions import (
    FritzActionError,
    FritzArgumentError,
    FritzLookUpError,
)
from ..core.utils import get_xml_root
from .fritzbase import AbstractLibraryBase


SERVICE = "Hosts1"
HOSTLIST_CONVERTERS = {
    'Index': int,
    'Active': bool,
    'X_AVM-DE_Port': int,
    'X_AVM-DE_Speed': int,
    'X_AVM-DE_UpdateAvailable': bool,
    'X_AVM-DE_Guest': bool,
    'X_AVM-DE_VPN': bool,
    'X_AVM-DE_Disallow': bool,
}


def _convert_host_attributes(host):
    """
    Helper function for FritzHosts.get_host_list().

    Takes a `host` which is an item-node (representing a host entry)
    from the xml-file returned from the lua script that gets called from
    the `path` returned from the `X_AVM-DE_GetHostListPath` action. The
    datatype of the nodes are documented here: ::

        https://avm.de/fileadmin/user_upload/Global/Service/¬
        Schnittstellen/hostsSCPD.pdf

    Converts the child-nodes of the node (the host-attributes) to the
    according datatypes and returns a dictionary with the child-node
    tags as keys and the converted content as values.
    """
    attributes = {}
    for attribute in host:
        try:
            value = HOSTLIST_CONVERTERS[attribute.tag](attribute.text)
        except KeyError:
            value = attribute.text
        attributes[attribute.tag] = value
    return attributes


class FritzHosts(AbstractLibraryBase):
    """
    Class to access the registered hosts. All parameters are optional. If
    given, they have the following meaning: `fc` is an instance of
    FritzConnection, `address` the ip of the Fritz!Box, `port` the port
    to connect to, `user` the username, `password` the password,
    `timeout` a timeout as floating point number in seconds, `use_tls` a
    boolean indicating to use TLS (default False).
    """

    def _action(self, actionname, *, arguments=None, **kwargs):
        return self.fc.call_action(SERVICE, actionname, arguments=arguments, **kwargs)

    @property
    def host_numbers(self):
        """The number of known hosts."""
        result = self._action("GetHostNumberOfEntries")
        return result["NewHostNumberOfEntries"]

    def get_generic_host_entry(self, index):
        """
        Returns a dictionary with information about a device internally
        registered by the position *index*. Index-positions are
        zero-based.
        """
        return self._action("GetGenericHostEntry", NewIndex=index)

    def get_generic_host_entries(self):
        """
        Generator returning a dictionary for every host as provided by
        `get_generic_host_entry()`. (See also `get_hosts_info()` that
        returns a list of dictionaries with different key-names.)
        """
        for index in itertools.count():
            try:
                yield self.get_generic_host_entry(index)
            except IndexError:
                break

    def get_specific_host_entry(self, mac_address):
        """
        Returns a dictionary with information about a device addressed
        by the MAC-address.
        """
        return self._action("GetSpecificHostEntry", NewMACAddress=mac_address)

    def get_specific_host_entry_by_ip(self, ip):
        """
        Returns a dictionary with information about a device addressed
        by the ip-address. Provides additional information about
        connection speed and system-updates for AVM devices.
        """
        return self._action("X_AVM-DE_GetSpecificHostEntryByIP", NewIPAddress=ip)

    def get_host_status(self, mac_address):
        """
        Provides status information about the device with the given
        `mac_address`. Returns `True` if the device is active or `False`
        otherwise. Returns `None` if the device is not known or the
        `mac_address` is invalid.
        """
        try:
            result = self.get_specific_host_entry(mac_address)
        except (FritzArgumentError, FritzLookUpError):
            return None
        return result["NewActive"]

    def get_active_hosts(self):
        """
        Returns a list of dicts with information about the active
        devices. The dict-keys are: 'ip', 'name', 'mac', 'status', 'interface_type', 'address_source', 'lease_time_remaining'
        """
        return [host for host in self.get_hosts_info() if host["status"]]

    def get_hosts_info(self):
        """
        Returns a list of dicts with information about the known hosts.
        The dict-keys are: 'ip', 'name', 'mac', 'status', 'interface_type', 'address_source', 'lease_time_remaining'
        """
        result = []
        for index in itertools.count():
            try:
                host = self.get_generic_host_entry(index)
            except IndexError:
                # no more host entries:
                break
            result.append(
                {
                    "ip": host["NewIPAddress"],
                    "name": host["NewHostName"],
                    "mac": host["NewMACAddress"],
                    "status": host["NewActive"],
                    "interface_type": host["NewInterfaceType"],
                    "address_source": host["NewAddressSource"],
                    "lease_time_remaining": host["NewLeaseTimeRemaining"],
                }
            )
        return result

    def get_host_list(self):
        """
        Returns a list of dictionaries with information about the known
        hosts according to `X_AVM-DE_GetHostListPath` action. The
        key-value pairs of a dictionary are:

        'Active': (bool)
            `True` If host is active, `False` if host is inactive
            (currently not connected)

        'HostName': (string)
            Name of the host device

        'Index': (int)
            Sequential number for each host

        'InterfaceType': (string)
            The interface with which the host accesses the F!Box
            (“Ethernet”, “802.11”, "HomePlug", “”)

        'IPAddress': (string)
             The host's ip address

        'MACAddress': (string)
            The host's MAC address

        'X_AVM-DE_Guest': (boolean)
            `True` if the host is connected with guest network, `False`
            if connected with home network

        'X_AVM-DE_InfoURL': (string)
            Link to a text file which contains the changelog of the last
            firmware update

        'X_AVM-DE_Model': (string)
            Model name or number of the F!device

        'X_AVM-DE_Disallow': (bool)
            Flag which represent the WAN access allowed state

        'X_AVM-DE_Port': (int)
            If host is connected via ethernet, it shows the port number

        'X_AVM-DE_Speed': (int)
            Shows the speed in Mbit/s

        'X_AVM-DE_UpdateAvailable': (bool)
            `True` if update is available, `False` if no new update is
            available

        'X_AVM-DE_UpdateSuccessful': (string)
            Shows the state of the last firmware update process
            ('unknown', 'failed','succeeded')

        'X_AVM-DE_URL': (string)

        'X_AVM-DE_VPN': (bool)
            `True` if host is a vpn connection else `False`.

        'X_AVM-DE_WANAccess': (string)
            Shows if the landevice has WAN access ('granted', 'denied', 'error')

        The values are converted to the documented datatype or `None` if
        no data available. Values from unknown keys that may be added by
        AVM in future versions are of type `string` or `None`.

        .. versionadded:: development
        """
        result = self._action("X_AVM-DE_GetHostListPath")
        path = result["NewX_AVM-DE_HostListPath"]
        url = f"{self.fc.address}:{self.fc.port}{path}"
        root = get_xml_root(url, session=self.fc.session)
        return [_convert_host_attributes(host) for host in root]

    def get_mesh_topology(self, raw=False):
        """
        Returns information about the mesh network topology. If `raw` is
        `False` the topology gets returned as a dictionary with a list
        of nodes. If `raw` is `True` the data are returned as text in
        json format. Default is `False`.
        """
        result = self._action("X_AVM-DE_GetMeshListPath")
        path = result["NewX_AVM-DE_MeshListPath"]
        url = f"{self.fc.address}:{self.fc.port}{path}"
        with self.fc.session.get(url) as response:
            if not response.ok:
                message = f"Error {response.status_code}: Device has no access to topology information."
                raise FritzActionError(message)
            return response.text if raw else response.json()

    def get_wakeonlan_status(self, mac_address):
        """
        Returns a boolean whether wake on LAN signal gets send to the
        device with the given `mac_address` in case of a remote access.
        """
        info = self._action(
            "X_AVM-DE_GetAutoWakeOnLANByMACAddress", NewMACAddress=mac_address
        )
        return info["NewAutoWOLEnabled"]

    def set_wakeonlan_status(self, mac_address, status=False):
        """
        Sets whether a wake on LAN signal should get send send to the
        device with the given `mac_address` in case of a remote access.
        `status` is a boolean, default value is `False`. This method has
        no return value.
        """
        args = {
            "NewMACAddress": mac_address,
            "NewAutoWOLEnabled": status,
        }
        self._action("X_AVM-DE_SetAutoWakeOnLANByMACAddress", arguments=args)

    def set_host_name(self, mac_address, name):
        """
        Sets the hostname of the device with the given `mac_address` to
        the new `name`.
        """
        args = {
            "NewMACAddress": mac_address,
            "NewHostName": name,
        }
        self._action("X_AVM-DE_SetHostNameByMACAddress", arguments=args)

    def get_host_name(self, mac_address):
        """
        Returns a String with the host_name of the device with the given mac_address
        """
        return self.get_specific_host_entry(mac_address)["NewHostName"]

    def run_host_update(self, mac_address):
        """
        Triggers the host with the given `mac_address` to run a system
        update. The method returns immediately, but for the device it
        takes some time to do the OS update. All vendor warnings about running a
        system update apply, like not turning power off during a system
        update. So run this command with caution.
        """
        self._action("X_AVM-DE_HostDoUpdate", NewMACAddress=mac_address)
