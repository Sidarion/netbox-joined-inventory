#!/usr/bin/env python3
# coding: utf-8

# Copyright: (c) 2018, Mario Gersbach <https://www.sidarion.ch/>
# Credits: Ahmed AbouZaid <http://aabouzaid.com/>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0.1

import os
import sys
import re
import time
from pathlib import Path
import yaml
import argparse
from operator import itemgetter

import distro

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

# allow requests to access the local certificate bundle
ca_file = 'ca-certificates.crt' if 'debian' in [distro.id(), distro.like()] else 'ca-bundle.crt'
os.environ.setdefault('REQUESTS_CA_BUNDLE', os.path.join('/etc/ssl/certs/', ca_file))

try:
    import requests
except ImportError:
    sys.exit('Requests package is required for this inventory script.')

try:
    import json
except ImportError:
    import simplejson as json

# Script.
def cli_arguments():
    """Script cli arguments.
    """

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-c", "--config-file",
                        default=os.getenv("NETBOX_CONFIG_FILE", "config/netbox_joined_inventory.yml"),
                        help="""Path for script's configuration. Also "NETBOX_CONFIG_FILE"
                                could be used as env var to set conf file path.""")
    arguments = parser.parse_args()
    return arguments

# Utils.
def open_yaml_file(yaml_file):
    """Open YAML file.
    Args:
        yaml_file: Relative or absolute path to YAML file.
    Returns:
        Content of YAML the file.
    """

    # Load content of YAML file.
    try:
        with open(yaml_file, 'r') as config_yaml_file:
            try:
                yaml_file_content = yaml.safe_load(config_yaml_file)
            except yaml.YAMLError as yaml_error:
                sys.exit(yaml_error)
    except IOError as io_error:
        sys.exit("Cannot open YAML file.\n%s" % io_error)
    return yaml_file_content


class NetboxJoinedInventory(object):
    """Netbox as a dynamic inventory for Ansible.
    Retrieves hosts list from netbox API and returns Ansible dynamic inventory (JSON).
    Attributes:
        script_config_data: Content of its config which comes from YAML file.
    """

    def __init__(self, script_config_data):
        # Script arguments.
        #self.config_file = script_args.config_file
        self.list = True # script_args.list
        self.host = False # script_args.host

        # Script configuration.
        self.script_config = script_config_data
        self.api_url = self._config(["main", "api_url"])
        assert (re.match('^https?://', self.api_url, flags=0)), "Wrong URL syntax in config file for api_url!"
        self.api_token = self._config(["main", "api_token"], default="", optional=True)
        self.group_by = self._config(["group_by"], default={})
        self.host_vars = self._config(["host_vars"], default={})

        # Get value based on key.
        self.key_map = {
            "default": "name",
            "general": "name",
            "custom": "label",
            "ip": "address"
        }

    def _get_value_by_path(self, source_dict, key_path,
                           ignore_key_error=False, default="", error_message=""):
        """Get key value from nested dict by path.
        Args:
            source_dict: The dict that we look into.
            key_path: A list has the path of key. e.g. [parent_dict, child_dict, key_name].
            ignore_key_error: Ignore KeyError if the key is not found in provided path.
            default: Set default value if the key is not found in provided path.
        Returns:
            If key is found in provided path, it will be returned.
            If ignore_key_error is True, None will be returned.
            If default is defined and key is not found, default will be returned.
        """

        key_value = ""
        if not error_message:
            error_message = "The key %s is not found. Please remember, Python is case sensitive."

        try:
            # Reduce key path, where it get value from nested dict.
            # a replacement for buildin reduce function.
            for key in key_path:
                if isinstance(source_dict.get(key), dict) and len(key_path) > 1:
                    source_dict = source_dict.get(key)
                    key_path = key_path[1:]
                    self._get_value_by_path(source_dict, key_path, ignore_key_error=ignore_key_error,
                                            default=default, error_message=error_message)
                else:
                    key_value = source_dict[key]

        # How to set the key value, if the key was not found.
        except KeyError as key_name:
            if default:
                key_value = default
            elif not default and ignore_key_error:
                key_value = None
            elif not key_value and not ignore_key_error:
                sys.exit(error_message % key_name)
        return key_value

    def _config(self, key_path, default="", optional=False):
        """Get value from config var.
        Args:
            key_path: A list has the path of the key.
            default: Default value if the key is not found.
        Returns:
            The value of the key from config file or the default value.
        """
        error_message = "The key %s is not found in config file."
        config = self.script_config.setdefault("netbox", {})
        key_value = self._get_value_by_path(config, key_path, ignore_key_error=optional,
                                            default=default, error_message=error_message)

        return key_value

    @lru_cache(maxsize=2048)
    def get_hosts_list(self, api_url, api_token=None, specific_id=None):
        """Retrieves hosts list from netbox API.
        Returns:
            A list of all hosts from netbox API.
        """
        api_url = str(api_url) + "api/dcim/devices/"

        api_url_params = {}
        if specific_id:
            api_url_params.update({"name": specific_id})

        # tenant filtering
        if self._config(["main", "tenant"]) and self._config(["main", "tenant"]) != '':
            api_url_params.update({"tenant": self._config(["main", "tenant"])})

        hosts_list = self.get_items_from_api(api_url, api_token, api_url_params)
        return hosts_list

    @lru_cache(maxsize=2048)
    def get_interfaces_list(self, api_url, api_token=None, specific_id=None):
        """Retrieves interfaces list from netbox API.
        Returns:
            A list of interfaces hosts from netbox API.
        """
        print("Getting all interfaces to populate cache")
        start_time = time.time()
        api_url = str(api_url) + "api/dcim/interfaces/"
        # api_url_params = {}
        # if specific_id:
        #     api_url_params.update({"device_id": specific_id})
        interfaces_list = self.get_items_from_api(api_url, api_token)
        print("Getting all interfaces took %s seconds." % round(time.time() - start_time, 1))
        return interfaces_list

    @lru_cache(maxsize=2048)
    def get_vlan_list(self, api_url, api_token=None, vlan_domain=None):
        """Retrieves vlan list that are attached to a device."""
        print("Getting  VLANs to populate cache for vlan_domain " + str(vlan_domain))
        api_url = str(api_url) + "api/ipam/vlans/"
        api_url_params = {}
        vlan_list = []
        if vlan_domain != None and vlan_domain != '':
            api_url_params.update({"role": vlan_domain})
            vlan_list = self.get_items_from_api(api_url, api_token, api_url_params)
        return vlan_list

    @lru_cache(maxsize=2048)
    def get_prefixes_cache(self, api_url, api_token=None):
        """Retrieves prefixes list that are attached to a device."""
        print("Getting all prefixes to populate cache")
        api_url = str(api_url) + "api/ipam/prefixes/"
        api_url_params = {}
        prefixes_list = self.get_items_from_api(api_url, api_token, api_url_params)

        prefixes_cache = {}
        for net in prefixes_list:
            if net['vlan'] != None:
                vid = net['vlan']['vid']
                prefixes_cache[vid] = { 'vid': vid,
                                            'description': str(net['description']),
                                            'cidr': net['prefix'],
                                            }
                # case: prefix without role or vlan role
                if net['vrf'] is not None:
                    prefixes_cache[vid]['vrf'] = net['vrf']['name']
                else:
                    prefixes_cache[vid]['vrf'] = None
        return prefixes_cache

    @lru_cache(maxsize=2048)
    def get_vrfs_cache(self, api_url, api_token=None):
        """Retrieves vrfs list that are attached to a device."""
        print("Getting all VRFs to populate cache")
        api_url = str(api_url) + "api/ipam/vrfs/"
        api_url_params = {}
        vrfs_list = self.get_items_from_api(api_url, api_token, api_url_params)

        vrfs_cache = {}
        for vrf in vrfs_list:
            vrf_name = vrf['name']
            vrfs_cache[vrf_name] = { 'description': vrf['description'],
                                     'name': vrf_name}
            if "gateway" in vrf['custom_fields']:
                vrfs_cache[vrf_name]['gateway'] = vrf['custom_fields']['gateway']
            else:
                vrfs_cache[vrf_name]['gateway'] = None
            if "dhcp_relay_servers" in vrf['custom_fields']:
                vrfs_cache[vrf_name]['dhcp_relay_servers'] = vrf['custom_fields']['dhcp_relay_servers']
            else:
                vrfs_cache[vrf_name]['dhcp_relay_servers'] = None
        return vrfs_cache

    @lru_cache(maxsize=2048)
    def get_ip_addresses_list(self, api_url, api_token=None, specific_id=None):
        """Retrieves ip_addresses list from netbox API.
        Returns:
            A list of ip_addresses hosts from netbox API.
        """
        api_url = api_url + "api/ipam/ip-addresses/"
        api_url_params = {}
        if specific_id:
            api_url_params.update({"device_id": specific_id})
        ip_addresses_list = self.get_items_from_api(api_url, api_token, api_url_params)
        return ip_addresses_list

    @staticmethod
    def get_items_from_api(api_url, api_token=None, api_url_params = {} ):
        # TODO: Hier würde ich die Doku sowie die Variablen etwas generalisieren und die Doku detaillierter machen
        """Retrieves a list of items from netbox API.
        Returns:
            A list of all hosts from netbox API.
        """

        if not api_url:
            sys.exit("Please check API URL in script configuration file.")

        api_url_headers = {}

        if api_token:
            api_url_headers.update({"Authorization": "Token %s" % api_token})

        items_list = []

        # Pagination. Max 1000
        api_url_params['limit'] = 1000
        while api_url:
            # Get list.
            api_output = requests.get(api_url, params=api_url_params, headers=api_url_headers)

            # Check that a request is 200 and not something else like 404, 401, 500 ... etc.
            api_output.raise_for_status()

            # Get api output data.
            api_output_data = api_output.json()

            # The retrieval of data is paginated to optimize the network footprint. The method follows the "next" field within the netbox-api's reply
            # to load all pages of data. Each page corresponds to an entry in the list which is returned.
            if isinstance(api_output_data, dict) and "results" in api_output_data:
                items_list += api_output_data["results"]
                api_url = api_output_data["next"]

        # Get hosts list.
        return items_list

    @staticmethod
    def add_host_to_group(server_name, group_value, inventory_dict):
        """Add a host to a single group.
        It checks if host is in the group and adds the host to that group.
        The group will be added if it's not in the inventory.
        Args:
            server_name: String, the server that will be added to a group.
            group_value: String, name that will be used as a group in the inventory.
            inventory_dict: Dict, the inventory which will be updated.
        Returns:
            The dict "inventory_dict" after adding the host to its group/s.
        """

        # The value could be None/null.
        if group_value:
            # If the group not in the inventory it will be add.
            if group_value not in inventory_dict:
                inventory_dict.update({group_value: []})

            # If the host not in the group it will be add.
            if server_name not in inventory_dict[group_value]:
                inventory_dict[group_value].append(server_name)
        return inventory_dict

    def add_host_to_inventory(self, groups_categories, inventory_dict, host_data):
        """Add a host to its groups.
        It checks if host in the groups and adds the host to these groups.
        The groups are defined in this inventory script config file.
        Args:
            groups_categories: Dict, it has a categories of groups that will be
                used as Ansible inventory groups.
            inventory_dict: Dict, which is Ansible inventory.
            host_data: Dict, it has the host data that will be added to inventory.
        Returns:
            The dict "inventory_dict" after adding the host to it.
        """

        server_name = host_data.get("name")
        categories_source = {
            "default": host_data,
            "custom": host_data.get("custom_fields")
        }

        if groups_categories:
            # There are 2 categories that will be used to group hosts.
            # One for default section in netbox, and another for "custom_fields" which are being defined by netbox user.
            for category in groups_categories:
                key_name = self.key_map[category]
                data_dict = categories_source[category]

                # The groups that will be used to group hosts in the inventory.
                for group in groups_categories[category]:
                    # Try to get group value. If the section not found in netbox, this also will print error message.
                    group_value = self._get_value_by_path(data_dict, [group, key_name])
                    if group_value == server_name:
                        raise ValueError("Group value error with {} {} {}".format(server_name, group, group_value))
                    inventory_dict = self.add_host_to_group(server_name, group_value, inventory_dict)

        # If no groups in "group_by" section, the host will go to catch-all group.
        else:
            if "no_group" not in inventory_dict:
                inventory_dict.setdefault("no_group", [server_name])
            else:
                inventory_dict["no_group"].append(server_name)
        return inventory_dict

    def get_host_vars(self, host_data, host_vars):
        """Find host vars.
        These vars will be used for host in the inventory.
        We can select whatever from netbox to be used as Ansible inventory vars.
        The vars are defined in script config file.
        Args:
            host_data: Dict, it has a host data which will be added to inventory.
            host_vars: Dict, it has selected fields to be used as host vars.
        Returns:
            A dict has all vars are associated with the host.
        """

        host_vars_dict = dict()
        if host_vars:
            categories_source = {
                "ip": host_data,
                "general": host_data,
                "custom": host_data.get("custom_fields")
            }

            # Get host vars based on selected vars. (that should come from
            # script's config file)
            for category in host_vars:
                key_name = self.key_map[category]
                data_dict = categories_source[category]

                for var_name, var_data in host_vars[category].items():
                    # This is because "custom_fields" has more than 1 type.
                    # Values inside "custom_fields" could be a key:value or a dict.
                    if isinstance(data_dict.get(var_data), dict):
                        var_value = self._get_value_by_path(data_dict, [var_data, key_name], ignore_key_error=True)
                    else:
                        var_value = data_dict.get(var_data)

                    if var_value:
                        # Remove CIDR from IP address.
                        if "ip" in host_vars and var_data in host_vars["ip"].values():
                            var_value = var_value.split("/")[0]
                        # Add var to host dict.
                        host_vars_dict.update({var_name: var_value})
        return host_vars_dict

    def update_host_meta_vars(self, inventory_dict, host_name, host_vars):
        """Update host meta vars.
        Add host and its vars to "_meta.hostvars" path in the inventory.
        Args:
            inventory_dict: A dict for inventory has groups and hosts.
            host_name: Name of the host that will have vars.
            host_vars: A dict has selected fields to be used as host vars.
        Returns:
            The dict "inventory_dict" after updating the host meta data.
        """

        if host_vars and not self.host:
            inventory_dict['_meta']['hostvars'].update({host_name: host_vars})
        elif host_vars and self.host:
            inventory_dict.update({host_name: host_vars})
        return inventory_dict

    def generate_inventory(self):
        """Generate Ansible dynamic inventory.
        Returns:
            A dict has inventory with hosts and their vars.
        """

        inventory_dict = dict()
        netbox_hosts_list = self.get_hosts_list(self.api_url, self.api_token, self.host)

        if netbox_hosts_list:
            inventory_dict.update({"_meta": {"hostvars": {}}})

            for current_host in netbox_hosts_list:
                print(current_host['name'] + " getting host_vars")

                server_name = current_host.get("name")
                self.add_host_to_inventory(self.group_by, inventory_dict, current_host)
                host_vars = self.get_host_vars(current_host, self.host_vars)

                # handle networking devices
                if self._config(["features", "join_interfaces"]) or self._config(["features", "join_vlan_roles"]):
                    host_vars.update(self.generate_networking_host_vars(current_host))

                inventory_dict = self.update_host_meta_vars(inventory_dict, server_name, host_vars)
        return inventory_dict

    def generate_networking_host_vars(self, current_host):

        host_vars = {}
        prefixes_cache = self.get_prefixes_cache(self.api_url, self.api_token)
        vrfs_cache = self.get_vrfs_cache(self.api_url, self.api_token)

        # Join interfaces data into network device
        if self._config(["features", "join_interfaces"]):
            #host_vars['interfaces'] = sorted(self.join_interfaces(current_host), key=itemgetter('name'))
            host_vars['interfaces'] = self.join_interfaces(current_host)
            host_vars['bridge_vids'] = self.get_bridge_vids(host_vars['interfaces'])

        # Join configured vlans and vrfs into network device
        if self._config(["features", "join_vlan_roles"]):
            host_vars['configured_vlans'] = []
            configured_vrfs = {}
            vlans_from_role = self.join_vlans(current_host)
            for vlan in vlans_from_role:
                if vlan['vid'] in prefixes_cache:
                    prefix_data = prefixes_cache[vlan['vid']]
                    prefix_data['anycast_ip'] = vlan['anycast_ip']
                    prefix_data['dhcp_relay_enabled'] = vlan['dhcp_relay_enabled']
                    prefix_data['status'] = vlan['status']
                    host_vars['configured_vlans'].append(prefix_data)
                    # Join configured vrfs into network device
                    if prefixes_cache[vlan['vid']]['vrf'] in vrfs_cache:
                        configured_vrfs[prefixes_cache[vlan['vid']]['vrf']] = vrfs_cache[prefixes_cache[vlan['vid']]['vrf']]
                    #else:
                    #    print("    WARN: missing vrf for vlan id " + str(vlan['vid']))
                else:
                    # no prefix found for VLAN ID
                    #print("    WARN: missing prefix for vlan id " + str(vlan['vid']))
                    host_vars['configured_vlans'].append({'vid': vlan['vid'],
                                                        'description':  vlan['name'],
                                                        'status': vlan['status']
                                                        })
            # sort the lists
            configured_vrf_list = list(configured_vrfs.values())
            configured_vrf_list = sorted(configured_vrf_list, key=(lambda configured_vrf_list_: configured_vrf_list_['gateway'] if configured_vrf_list_['gateway'] else ""))
            host_vars['configured_vrfs'] = configured_vrf_list
            host_vars['configured_vlans'] = sorted(host_vars['configured_vlans'], key=itemgetter('vid'))

            # Join cluster partner data e.g. clag backup ip
            if self._config(["features", "join_cluster_partner_data"]):
                try:
                    if current_host.get("custom_fields").get("cluster_role"):
                        role = current_host.get("custom_fields").get("cluster_role").get("label")
                        if role == "master" or role == "slave":
                            host_vars['cluster_partner_primary_ip'] = self.get_cluster_partner(current_host).get("primary_ip").get("address").split("/")[0]

                            # Join bridge vids from current host and from cluster partner
                            partner_host = self.get_cluster_partner(current_host)

                            partner_vars = {}
                            partner_vars['interfaces'] = self.join_interfaces(partner_host)

                            current_host_vids = self.get_bridge_vids(host_vars['interfaces'])
                            partner_host_vids = self.get_bridge_vids(partner_vars['interfaces'])
                            cluster_bridge_vids = list(set().union(current_host_vids, partner_host_vids))
                            cluster_bridge_vids.sort()
                            host_vars['cluster_bridge_vids'] = cluster_bridge_vids

                except:
                    print("Error getting partner_primary_ip. Please verify device cluster_role and peerlink_mac.")
                    raise

        return host_vars

    def get_cluster_partner(self, current_host):
        peerlink_mac = current_host.get("custom_fields").get("peerlink_mac")
        securityblock = current_host.get("custom_fields").get("securityblock")

        netbox_hosts_list = self.get_hosts_list(self.api_url, self.api_token, self.host)
        partner_host = None
        if netbox_hosts_list:
            for i_host in netbox_hosts_list:
                temp_peerlink_mac = i_host.get("custom_fields").get("peerlink_mac")
                temp_peersecurityblock = i_host.get("custom_fields").get("securityblock")

                if temp_peerlink_mac == peerlink_mac and securityblock == temp_peersecurityblock:
                    if not i_host.get("name") == current_host.get("name"):
                        assert(temp_peerlink_mac is not None), "This host must be a cluster member and have a peerlink_mac"
                        partner_host = i_host
                        break
        return partner_host

    def get_bridge_vids(self, interfaces_dict):
        bridge_vids_list = []
        for interface in interfaces_dict:
            #print released.get("iphone 3G", "none")
            if interface['untagged_vlan'] is not None:
                if interface['untagged_vlan'] not in bridge_vids_list:
                    bridge_vids_list.append(interface['untagged_vlan'])
            if interface['tagged_vlans']:
                for tagged_vlan in interface['tagged_vlans']:
                    if tagged_vlan not in bridge_vids_list:
                            bridge_vids_list.append(tagged_vlan)
        return bridge_vids_list

    def join_interfaces(self, current_host):
        """ For network devices try to join the interfaces """
        #print("    Getting interfaces for " + current_host['name'])
        #raw_interfaces = self.get_interfaces_list(self.api_url, self.api_token, specific_id=current_host.get("id"))

        all_interfaces = self.get_interfaces_list(self.api_url, self.api_token)
        raw_interfaces = []
        for interface in all_interfaces:
            if interface['device']['name'] == current_host['name']:
                raw_interfaces.append(interface)

        # get ip addresses for device
        raw_ip_addresses = self.get_ip_addresses_list(self.api_url, self.api_token, specific_id=current_host.get("id"))

        # prepare bond-slaves
        bond_dict = {}
        for raw_interface in raw_interfaces:
            bond_dict[raw_interface['name']] = []
        for raw_interface in raw_interfaces:
            if raw_interface['lag'] is not None:
                bond_dict[raw_interface['lag']['name']].append(raw_interface['name'])

        interfaces = []
        for raw_interface in raw_interfaces:

            # VLANs
            untagged_vlan = None
            if raw_interface ['untagged_vlan'] is not None:
                untagged_vlan = self._get_value_by_path(raw_interface, ['untagged_vlan', 'vid'])
            tagged_vlans = []
            if raw_interface['tagged_vlans'] is not None:
                for vlan in raw_interface['tagged_vlans']:
                    tagged_vlans.append(vlan['vid'])

            # Attach ip address
            ip_address = None
            vrf = None
            for raw_ip_address in raw_ip_addresses:
                if raw_ip_address['interface']['id'] == raw_interface['id']:
                    ip_address = raw_ip_address['address']
                    vrf = raw_ip_address['vrf']

            # LAG (redundant with bond_slaves)
            lag = None
            if raw_interface['lag'] is not None:
                lag = raw_interface['lag']['name']

            # VLAN mode : None, Tagged All, Tagged, Access
            mode = None
            if raw_interface['mode'] is not None:
                mode = raw_interface['mode']['label']

            # Try to generate clag-id out of interface name
            clag_id = None
            if raw_interface['form_factor']['label'] == "Link Aggregation Group (LAG)":
                if_name = raw_interface['name']
                if re.match('.*[0-9][0-9]$', if_name, flags=0):
                    clag_id = if_name[-2:]
                elif re.match('.*[0-9]$', if_name, flags=0):
                    clag_id = if_name[-1:]

            # Try to generate vid out of interface name of virtual interfaces
            vif_vid = None
            if raw_interface['form_factor']['label'] == "Virtual":
                if_name = raw_interface['name']
                assert (re.match('^vlan[0-9]+', if_name, flags=0) or if_name == "lo"), "Wrong syntax of virtual interface " + if_name
                if if_name.startswith("vlan"):
                    vif_vid = re.match('^vlan([0-9]+)', if_name, flags=0)
                    if vif_vid:
                        vif_vid = vif_vid.group(1)

            # join interface and ip into device
            interfaces.append({'name': raw_interface['name'],
                        'description': raw_interface['description'],
                        'enabled': raw_interface['enabled'],
                        'mode': mode,
                        'untagged_vlan': untagged_vlan,
                        'tagged_vlans' : tagged_vlans,
                        'address' : ip_address,
                        'vrf' : vrf,
                        'lag' : lag,
                        'clag_id' : clag_id,
                        'bond_slaves': bond_dict[raw_interface['name']],
                        'form_factor' : raw_interface['form_factor']['label'],
                        'vid' : vif_vid
            })
        return interfaces


    def join_vlans(self, current_host):
        """ For network devices try to join the untagged VLANs using the vlan role"""
        #print("    Getting attached VLANs for " + current_host['name'])

        # try to get VLAN_domain for this device
        vlan_domain = None
        vlan_list = []
        if "VLAN_domain" in current_host.get("custom_fields"):
            vlan_domain = current_host.get("custom_fields").get("VLAN_domain")
            if vlan_domain != None:
                raw_vlans = self.get_vlan_list(self.api_url, self.api_token, vlan_domain=vlan_domain['label'])

                for raw_vlan in raw_vlans:
                    # join vlan
                    vlan_dict = ({ "vid": raw_vlan['vid'],
                                       "name": raw_vlan['name'],
                                       "status": raw_vlan['status']["label"],
                                    })
                    if "anycast_ip" in raw_vlan['custom_fields']:
                        vlan_dict["anycast_ip"] = raw_vlan['custom_fields']['anycast_ip']
                    else:
                        vlan_dict["anycast_ip"] = None
                    if "dhcp_relay_enabled" in raw_vlan['custom_fields']:
                        if raw_vlan['custom_fields']['dhcp_relay_enabled'] is None or raw_vlan['custom_fields']['dhcp_relay_enabled'] is False:
                            vlan_dict["dhcp_relay_enabled"] = False
                        else:
                            vlan_dict["dhcp_relay_enabled"] = True
                    else:
                        vlan_dict["dhcp_relay_enabled"] = False # DB migration
                    vlan_list.append(vlan_dict)

        return vlan_list


    def print_inventory_json(self, inventory_dict):
        """Print inventory.
        Args:
            inventory_dict: Inventory dict has groups and hosts.
        Returns:
            It prints the inventory in JSON format if condition is true.
        """

        if self.host:
            result = inventory_dict.setdefault(self.host, {})
        elif self.list:
            result = inventory_dict
        else:
            result = {}
        print(json.dumps(result, indent=4))


    # writing inventory
    def write_ini_invetory(self, inv_dict):
        """ Writing an ini-like file with groups as sections"""
        ini = "# inventory ini\n"
        for key in inv_dict:
            if key != "_meta":
                ini = ini + "[" + str(key) + "]\n"
                for item in inv_dict[key]:
                    ini = ini + item + "\n"

        try:
            stream = open(self._config(["main", "inventory_output_file"]), 'w')
        except FileNotFoundError:
            print("FileNotFoundError: Please change configuration for inventory_output_file")
            raise
        stream.write(ini)
        stream.close()


    # writing host_var files
    def write_host_vars_file(self, host_name, host_vars_dict):
        """ Writing an yml file with the hosts vars"""
        try:
            stream = open(self._config(["main", "hostvars_output_folder"]) + host_name + '.yml', 'w')
        except FileNotFoundError:
            print("FileNotFoundError: Please change configuration for hostvars_output_folder")
            raise
        yaml.dump(host_vars_dict, stream, explicit_start=True, width=2048)
        stream.close()


    def purge_host_vars(self, pattern):
        """ clean directory """
        dir = self._config(["main", "hostvars_output_folder"])
        # for f in os.listdir(dir):
        #     if re.search(pattern, f):
        #         os.remove(os.path.join(dir, f))
        for p in Path(dir).glob(pattern):
            p.unlink()

# Main.
def main():
    # cli arguments and config file
    args = cli_arguments()
    config_data = open_yaml_file(args.config_file)

    # Netbox operation
    print("Start reading from netbox")
    netbox_inv = NetboxJoinedInventory(config_data)
    full_inventory = netbox_inv.generate_inventory()
    if full_inventory == {}:
        print("No devices found")
    else:
        #netbox_inv.print_inventory_json(full_inventory)

        # inventory file
        print("Start generating inventory")
        netbox_inv.write_ini_invetory(full_inventory)

        # host_vars files
        print("Start generating host_vars files")
        devices = full_inventory['_meta']['hostvars']
        netbox_inv.purge_host_vars("*.yml")
        for device_name in devices:
            netbox_inv.write_host_vars_file(device_name, devices[device_name])

# Run main.
if __name__ == "__main__":
    start_time = time.time()
    main()
    print("Inventory script ended. It took %s seconds." % round(time.time() - start_time, 1))
