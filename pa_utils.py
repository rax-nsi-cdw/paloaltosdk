import requests
import warnings
import re
import logging
from urllib.parse import quote
import time
import xml.etree.ElementTree as ET
import xmltodict
# import json
import datetime

from paloaltosdk.local_exceptions import EmptySourceTranslationForRule
from paloaltosdk.local_exceptions import EmptyDirectionForRule, EmptyAddressGroup
from tqdm import tqdm

warnings.filterwarnings("ignore")


class PanRequests:

    def __init__(self, logging_format='%(message)s'):
        self.Username = ''
        self.Password = ''
        self.IP = ""
        self.APIPort = 443
        self.pan_rest_version = ""
        self.headers = {"Content-Type": "application/json"}
        self._logging_format = logging_format
        logging.basicConfig(level=logging.CRITICAL, format=self.logging_format)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.CRITICAL)
        self.today = datetime.datetime.now().strftime("%Y-%m-%d")

    @property
    def logging_format(self):
        return self._logging_format

    @logging_format.setter
    def logging_format(self, logging_format):
        self._logging_format = logging_format
        logging.basicConfig(level=logging.INFO, format=self._logging_format)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)

    def _post_req(self, uri, payload=None):

        response = requests.post(f"https://{self.IP}:{self.APIPort}/{uri}",
                                 headers=self.headers, json=payload,
                                 verify=False)

        return response

    def _get_req(self, uri):

        response = requests.get(f"https://{self.IP}:{self.APIPort}/{uri}", headers=self.headers,

                                verify=False)

        return response

    def _del_req(self, uri):

        response = requests.delete(f"https://{self.IP}:{self.APIPort}/{uri}", headers=self.headers,

                                   verify=False)

        return response

    def _put_req(self, uri, payload):

        response = requests.put(f"https://{self.IP}:{self.APIPort}/{uri}", headers=self.headers,
                                json=payload,
                                verify=False)

        return response


class DeletionResponse:
    def __init__(self, requests_resp, referenced_groups_deleted=None,
                 referenced_rules_deleted=None, referenced_addr_objects_deleted=None, object=None):

        self._requests_resp = requests_resp
        self.object = object
        self.referenced_groups_deleted = referenced_groups_deleted
        self.referenced_rules_deleted = referenced_rules_deleted
        self.referenced_addr_objects_deleted = referenced_addr_objects_deleted

        try:
            self.status_code = requests_resp.status_code
        except Exception as e:
            self.logger.error(e)
            self.status_code = None

        def __str__(self):
            return self._requests_resp.json()


class _PanPaloShared(PanRequests):

    def __init__(self):
        super().__init__()
        self.rest_uri = ""
        self.xml_uri = "/api/"

    @staticmethod
    def watch(jobId, pb_description="Progress"):

        total = 100  # Total progress count (100%)
        with tqdm(total=total, desc=pb_description, 
                  bar_format='Fore.LIGHTBLUE_EX + "{l_bar}{bar:25}|"') as pbar:
            while True:
                job_status = _PanPaloShared.check_status_of_job(jobId)
                progress = int(job_status['progress'])
                if progress > 100:
                    progress = 100
                pbar.update(progress - pbar.n)  # Update progress bar to the current progress
                if progress >= 100:

                    break
                time.sleep(1)

    @staticmethod
    def xml_to_json(resp):
        xml_content = resp.content
        dict_content = xmltodict.parse(xml_content)
        return dict_content

    def commit(self, watch=False, force=False, target=None):
        '''
        returns job ID

        IF no job ID then returns None
        '''
        uri = (f"?key={self.headers['X-PAN-Key']}&type=commit&cmd=<commit></commit>"
               if not force else
               f"?key={self.headers['X-PAN-Key']}&type=commit&cmd=<commit><force></force></commit>")

        if target:
            uri += f'&target={target}'
        self.logger.info("Committing changes..")
        # print("\nCommitting changes..")
        resp = self._get_req(self.xml_uri+uri)
        responseXml = ET.fromstring(resp.content)

        try:
            jobId = responseXml.find('result').find('job').text

            if not watch:
                # even if watching, this verifies if there is indeed a job id.
                # There won't be one if there is nothing to commit
                return jobId
        except Exception as e:
            self.logger.error(e)
            return None

            if watch:
                _PanPaloShared.watch(jobId, pb_description="Commit Progress")

    def push_to_devices(self, watch=False):
        '''
        returns job ID

        IF no job ID then returns None
        '''
        uri = (
            f"?key={self.headers['X-PAN-Key']}&type=commit&action=all&cmd="
            "<commit-all><shared-policy><admin><member>"
            f"{self.Username}</member></admin></shared-policy></commit-all>"
            )

        self.logger.info("Pushing changes..")
        # print("\nPushing changes..")
        resp = self._get_req(self.xml_uri+uri)
        responseXml = ET.fromstring(resp.content)

        try:
            jobId = responseXml.find('result').find('job').text
            # even if watching, this verifies if there is indeed a job id.
            # There won't be one if there is nothing to commit
            if not watch:  
                return jobId
        except Exception as e:
            self.logger.error(e)
            return None

        if watch:
            _PanPaloShared.watch(jobId, pb_description="Push to Devices Progress")

    def login(self):

        # the quote function is encoding the password string. Ran into issues with requests not
        #  successfully encoding strings. For Example, anything with ### in the string.
        self.Password = quote(self.Password)

        uri = f'?type=keygen&user={self.Username}&password={self.Password}'
        try:
            resp = self._post_req(self.xml_uri+uri)
            resp.raise_for_status()
            self.LoggedIn = True
            responseXml = ET.fromstring(resp.content)
            key = responseXml.find('result').find('key')
            self.headers['X-PAN-Key'] = key.text
            try:
                self.sw_version = self.get_api_version()
                self.api_version = re.search('\d+\.\d+', self.sw_version).group(0)
                self.rest_uri = f"/restapi/v{self.api_version}/"
            except Exception as e:
                self.sw_version = None
                raise e
        except Exception:

            if 'invalid credential' in resp.content.decode('utf-8').lower():
                self.logger.info(resp.content)
                # print(resp.content)
                raise Exception("Invalid Credentials.")
            else:
                raise Exception(resp.content)

    def check_status_of_job(self, jobID):
        '''

        check status goes from ACT
        check result'''

        uri = f"?key={self.headers['X-PAN-Key']}&type=op&cmd=<show><jobs><id>{jobID}</id></jobs>" \
              f"</show>"

        resp = self._get_req(self.xml_uri+uri)
        responseXml = ET.fromstring(resp.content)

        try:
            return {"status": responseXml.find('result').find('job').find('status').text,

                    "result": responseXml.find('result').find('job').find('result').text,
                    "progress": responseXml.find('result').find('job').find('progress').text
                    }
        except Exception as e:
            return {"error": e, "api_response": resp.content}


class PanoramaAPI(_PanPaloShared):

    # rest_uri = f"/restapi/{self.sw_version}"
    # xml_uri = "/api/"

    def __init__(self, panorama_mgmt_ip=None):
        super().__init__()
        if panorama_mgmt_ip:
            self.IP = panorama_mgmt_ip
        self.LoggedIn = False

    @staticmethod
    def _convert_reference_response_to_list(references_string):
        """
        This is used when trying to delete an object,
        but the response from API call is that the object is referenced in other places
        like rules or groups.

        This will take the string of that gives 
        where the references are located and converts it to a list

        This is needed because the references come back in one big string
        """
        # validate it is a reference
        if "cannot be deleted because of references from:" not in references_string:
            raise ValueError("Did not pass a string that is a Palo Alto reference as an argument")

        references = []
        _shared = None
        references_string_split = re.split(r'(?<=\.  )', references_string)

        if references_string_split:

            for i in references_string_split:
                _shared = re.match('^shared -> (.*)', i)
                if i:
                    if "cannot be deleted because of references from:" not in i:
                        ref = {}
                        ref_reg = re.match("device-group -> (.*?(?=\->))->(.*)", i)
                        if _shared:
                            ref['device-group'] = "shared"
                            ref['reference'] = _shared.group(1).strip()
                        else:
                            ref['device-group'] = ref_reg.group(1).strip()
                        # FIXME: run function to validate valid device-group here
                            ref['reference'] = ref_reg.group(2).strip()
                        references.append(ref)

        else:
            raise Exception(f"Unable to split reference string: {references_string} ")

        return references

    def get_api_version(self):

        uri = f"?type=version&key={self.headers['X-PAN-Key']}"

        resp = self._get_req(self.xml_uri+uri)

        responseXml = ET.fromstring(resp.content)
        return responseXml.find('result').find('sw-version').text
        # return {"status": responseXml.find('result').find('job').find('status').text,

    def get_devices(self):

        uri = '?type=op&cmd=<show><devices><all></all></devices></show>'

        resp = self._get_req(self.xml_uri+uri)
        return self.xml_to_json(resp)['response']['result']['devices']['entry']

    def get_sys_info(self, sn):
        uri = f'?type=op&cmd=<show><system><info></info></system></show>&target={sn}'
        resp = self._get_req(self.xml_uri+uri)
        return self.xml_to_json(resp)['response']

    def config_xml_generic(self, xpath, serial=None, action="get"):
        '''Used to get configuration data'''
        if serial is not None:
            uri = f"?type=config&target={serial}&action=get&xpath={xpath}"
        else:
            uri = f"?type=config&action={action}&xpath={xpath}"
        # print(uri)
        resp = self._get_req(self.xml_uri+uri)
        return self.xml_to_json(resp)['response']

    def get_sys_limits(self, sn, filter='cfg.general.max*'):

        uri = (
            f'?type=op&cmd=<show><system><state><filter>{filter}</filter></state>'
            f'</system></show>'
            f'&target={sn}'
        )
        resp = self._get_req(self.xml_uri+uri)
        return self.xml_to_json(resp)['response']['result']

    def get_vsys_max(self, sn):

        sys_limit_resp = self.get_sys_limits(sn, filter='cfg.general.max-vsys*')

        max_vsys_in_hex = re.search('max-vsys:\s+(0x.*)', sys_limit_resp)
        if max_vsys_in_hex:
            return int(max_vsys_in_hex.group(1), 16)

        max_vsys = re.search('max-vsys:\\s+(\\d+)', sys_limit_resp)

        if max_vsys:
            return int(max_vsys.group(1))

        return None

    def get_current_used_vsys(self, sn, devices=None):
        if devices is None:
            devices = self.get_devices()
        for device in devices:
            if device['serial'] == sn:
                if 'vsys' in device and 'entry' in device['vsys']:
                    return len(device['vsys']['entry'])
        return None

    def get_remaining_vsys(self, sn=None):
        """
        returns the number (int) of vsys unused

        if no sn specified, method will pull all devices.

        Firewall must be in multi vsys mode to have return data
        """

        if sn:
            try:
                return self.get_vsys_max(sn) - self.get_current_used_vsys(sn)
            except Exception as e:
                self.logger.error(e)
                return None

    def get_vsys_tags(self, sn, vsys_name):
        '''Returns tags for a vsys'''
        xpath = f"/config/devices/entry/vsys/entry[@name='{vsys_name}']/tag"
        resp = self.config_xml_generic(xpath=xpath, serial=sn, action='get')
        if (resp['result'] is not None and
                'tag' in resp['result'] and
                'entry' in resp['result']['tag']):
            return resp['result']['tag']['entry']
        else:
            return None  # or any default value you prefer

    def get_all_vsys_tags(self, devices: list):
        for device in devices:
            if device['multi-vsys'] == "yes":
                vsys_tags = []
                for vsys in device['vsys']['entry']:
                    tags = self.get_vsys_tags(device['serial'], vsys['@name'])
                    vsys_tags.append({'vsys': vsys['@name'], 'tags': tags})
                return vsys_tags

    def get_vsys_fields(self, devices: str, get_tags=False) -> list:
        ''' maps out vsys fields for each device'''
        devices_vsys = []
        for device in devices:
            if device['multi-vsys'] == "yes":
                vsys_free = self.get_remaining_vsys(device['serial'])
                vsys_max = self.get_vsys_max(device['serial'])
                vsys_data = {'hostname': device['hostname'],
                             'serial': device['serial'],
                             'vsys_free': vsys_free,
                             'vsys_max': vsys_max,
                             "ha_peer": device['ha']['peer']['serial'] if 'ha' in device else None}
                vsys_in_use = []
                for vsys in device['vsys']['entry']:
                    # Show devices doesn't have detailed vsys info (tags). Optionally retrieve tags
                    if get_tags:
                        tags = self.get_vsys_tags(device['serial'], vsys['@name'])
                        vsys_in_use.append({'@name': vsys['@name'],
                                            "display-name": vsys['display-name'], "tags": tags})
                    else:
                        vsys_in_use.append({'@name': vsys['@name'],
                                            "display-name": vsys['display-name']})
                vsys_data['vsys_in_use'] = vsys_in_use
                vsys_data['vsys_used'] = len(vsys_in_use)
                devices_vsys.append(vsys_data)
        return devices_vsys

    def get_vsys_data(self, combine_ha=True, devices=None):
        """
        returns number of used and available vsys. Includes tags

        if no sn specified, method will pull all devices.

        Firewall must be in multi vsys mode to have return data
        """
        devices_vsys = []
        if devices is None:
            devices = self.get_devices()

        devices_vsys = self.get_vsys_fields(devices)

        if combine_ha:
            device_vsys_combined_ha = []
            device_peers_added_to_device_vsys_combined_ha = []

            for device in devices_vsys:
                if not device['ha_peer']:
                    del device['ha_peer']
                    device_vsys_combined_ha.append(device)
                    continue
                if device['serial'] not in device_peers_added_to_device_vsys_combined_ha:
                    # storing peer data in memory in next lines to use later
                    ha_peer_data = None
                    for d in devices_vsys:
                        if d['serial'] == device['ha_peer']:
                            ha_peer_data = d
                            break
                    # Combining serials with higher serial first ex: 1000_200
                    higher_serial = max(device['serial'], ha_peer_data['serial'])
                    lower_serial = min(device['serial'], ha_peer_data['serial'])
                    combined_serial = f"{higher_serial}_{lower_serial}"
                    # Combining hostname and making sure the higher

                    # serial hostname is first by the following logic
                    higher_hostname = None
                    lower_hostname = None

                    if device['serial'] == higher_serial:
                        higher_hostname = device['hostname']
                        lower_hostname = ha_peer_data['hostname']
                    else:
                        higher_hostname = ha_peer_data['hostname']
                        lower_hostname = device['hostname']
                    if not higher_hostname or not lower_hostname:
                        raise Exception("Unable to determine hostname for HA Peers")
                    combined_hostname = f"{higher_hostname}_{lower_hostname}"
                    ha_combined_vsys_data = {"serial": combined_serial,
                                             "hostname": combined_hostname
                                             }
                    if (
                        device['vsys_max'] == ha_peer_data['vsys_max'] and
                        device['vsys_used'] == ha_peer_data['vsys_used'] and
                        device['vsys_free'] == ha_peer_data['vsys_free'] and
                        device['vsys_in_use'] == ha_peer_data['vsys_in_use']
                    ):
                        ha_combined_vsys_data['vsys_max'] = device['vsys_max']
                        ha_combined_vsys_data['vsys_used'] = device['vsys_used']
                        ha_combined_vsys_data['vsys_free'] = device['vsys_free']
                        ha_combined_vsys_data['vsys_in_use'] = device['vsys_in_use']
                        ha_combined_vsys_data['Synced'] = True
                    else:
                        # HA Peers are not synced
                        ha_combined_vsys_data['vsys_max'] = None
                        ha_combined_vsys_data['vsys_used'] = None
                        ha_combined_vsys_data['vsys_free'] = None
                        ha_combined_vsys_data['vsys_in_use'] = None
                        ha_combined_vsys_data['Synced'] = False

                    device_peers_added_to_device_vsys_combined_ha.append(ha_peer_data['serial'])
                    device_vsys_combined_ha.append(ha_combined_vsys_data)

            return device_vsys_combined_ha
        return devices_vsys

    def get_devicegroups(self, include_shared=False):

        uri = 'Panorama/DeviceGroups'

        resp = self._get_req(self.rest_uri+uri)
        if resp.ok and 'entry' in resp.json()['result']:
            if include_shared:
                resp = resp.json()
                resp['result']['entry'].append({"@name": "shared"})
                return resp['result']['entry']
            else:
                return resp.json()['result']['entry']
        elif (resp.ok and "@total-count" in resp.json()['result'] and
                          resp.json()['result']['@total-count'] == "0"):
            return []  # empty
        return resp.json()

    def get_addresses(self, device_group):

        if device_group.lower() != "shared":
            uri = f'Objects/Addresses?location=device-group&device-group={device_group}'
        else:
            uri = f'Objects/Addresses?location={device_group}'

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry']
        elif resp.ok and "@total-count" in resp.json()['result'] and \
                resp.json()['result']['@total-count'] == "0":
            return []  # empty
        return resp

    def create_address(self, name, device_group, ip_netmask, description=""):

        if device_group.lower() != "shared":
            uri = f'Objects/Addresses?location=device-group&device-group={device_group}&name={name}'
        else:
            uri = f'Objects/Addresses?location={device_group}&name={name}'

        payload = {
            "entry": {
                "ip-netmask": ip_netmask,
                "@name": name,
                "description": description
            }
        }

        resp = self._post_req(self.rest_uri+uri, payload)

        return resp.json()

    def get_addressgroup(self, address_group, device_group):

        if device_group.lower() != "shared":
            uri = (
                f'Objects/AddressGroups?location=device-group&device-group={device_group}'
                f'&name={address_group}'
            )
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={address_group}'

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and "@total-count" in resp.json()['result'] and \
                int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple address groups detected for address group '{address_group}' "
                            f"in Device Group '{device_group}'")

        elif resp.ok and "@total-count" in resp.json()['result'] and \
                resp.json()['result']['@total-count'] == "0":
            return []  # empty

        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]

    def create_address_group(self, name, device_group, members=[], description=""):

        if device_group.lower() != "shared":
            uri = f'Objects/AddressGroups?location=device-group&device-group={device_group}&name={name}'
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={name}'

        payload = {
            "entry": {
                "static": {"member": members if isinstance(members, list) else [members]},
                "@name": name,
                "description": description
            }
        }

        resp = self._post_req(self.rest_uri+uri, payload)

        return resp.json()

    def delete_address_group(self,
                             address_group, device_group,
                             force=False,
                             force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references

        (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: This will do the same as force
          AND will remove references of references, etc.

        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced
          to same value. To have different values, set them both manually !!!!!
        '''

        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")

        if force_deletion_of_all_objects_referenced is None:
            force_deletion_of_all_objects_referenced = force

        if device_group.lower() != "shared":
            uri = (
                f'Objects/AddressGroups?location=device-group&device-group={device_group}'
                f'&name={address_group}'
            )
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={address_group}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return DeletionResponse(
                requests_resp=resp,
                referenced_groups_deleted=None,
                referenced_rules_deleted=None,
                object=address_group
            )

        if "@status" in resp.json().keys() and resp.json()['@status'] == 'success':
            return DeletionResponse(
                requests_resp=resp,
                referenced_groups_deleted=None,
                referenced_rules_deleted=None,
                object=address_group
            )

        # If object can't be deleted because of references, this will delete refs if force switch == True

        reference_remove_resp = self._filter_and_remove_obj_references(
            resp.json(), address_group, device_group, force=force)

        # self._delete_refs_of_refs(resp.json())

        resp2 = self._del_req(self.rest_uri+uri)
        self.logger.info(f"Deleted references. Now deleting address group {address_group} object.")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            self.logger.info(f"Deleted address group object {address_group}")
            return DeletionResponse(requests_resp=resp2,
                                    referenced_groups_deleted=reference_remove_resp.referenced_groups_deleted,
                                    referenced_rules_deleted=reference_remove_resp.referenced_rules_deleted,
                                    object=address_group)
        else:
            try:
                raise Exception(f"Unable to delete object '{address_group}'. \n"
                                f"Error: {resp2.json()}")
            except Exception as e:
                self.logger.error(e)
                raise Exception(f"Unable to delete object '{address_group}'.")

    def delete_address(self,
                       address_name,
                       device_group, force=False,
                       force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references 
        (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: 
        This will do the same as force AND will remove references of references, etc.

        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced
          to same value. To have different values, set them both manually !!!!!
        '''
        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")

        if force_deletion_of_all_objects_referenced is None:
            force_deletion_of_all_objects_referenced = force

        if device_group.lower() != "shared":
            uri = ('Objects/Addresses?location=device-group&device-group='
                   f'{device_group}&name={address_name}')
        else:
            uri = f'Objects/Addresses?location={device_group}&name={address_name}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return DeletionResponse(requests_resp=resp,
                                    referenced_groups_deleted=None,
                                    referenced_rules_deleted=None,
                                    object=address_name)

        if "@status" in resp.json() and resp.json()['@status'] == 'success':
            return DeletionResponse(requests_resp=resp,
                                    referenced_groups_deleted=None,
                                    referenced_rules_deleted=None,
                                    object=address_name)

        # If object can't be deleted because of references,
        #  this will delete refs if force switch == True

        reference_remove_resp = self._filter_and_remove_obj_references(
            resp.json(), address_name, device_group, force=force)

        resp2 = self._del_req(self.rest_uri+uri)
        self.logger.info(f"Deleted references. Now deleting address object {address_name}.")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            self.logger.info(f"Deleted address object {address_name}")
            return DeletionResponse(requests_resp=resp2,
                                    referenced_groups_deleted=reference_remove_resp.referenced_groups_deleted,
                                    referenced_rules_deleted=reference_remove_resp.referenced_rules_deleted,
                                    object=address_name)
        else:
            try:
                raise Exception(f"Unable to delete object '{address_name}'."
                                f"\n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_name}'.")

    # @staticmethod
    # def _convert_reference_response_to_list(references_string):
    #     """
    #     This is used when trying to delete an object,

    #     but the response from API call is that the object is referenced in other places
    #     like rules or groups.

    #     This will take the string of that gives where the references
    #  are located and converts it to a list

    #     This is needed because the references come back in one big string
    #     """
    #     # validate it is a reference
    #     if "cannot be deleted because of references from:" not in references_string:
    #         raise ValueError("Did not pass a string that is a Palo Alto reference as an argument")

    #     references = []
    #     for i in references_string.split('device-group ->'):

    #         if not "cannot be deleted because of references from:" in i:
    #             ref = {}
    #             r = re.match("((.*?)->)(.*)", i)
    #             ref['device-group'] = r.group(2).strip()
    #             # FIXME: run function to validate valid device-group here
    #             ref['reference'] = r.group(3).strip()
    #             references.append(ref)
    #     return references

    def remove_address_from_rule(self, address_name,
                                 rule_name,
                                 rule_type,
                                 rulebase,
                                 device_group,
                                 direction,
                                 force=False,
                                 translation_direction=None,
                                 translation_type=None):
        '''
        '''

        if not type(rulebase) is str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")

        if device_group.lower() != "shared":
            uri = (
                f'Policies/{rule_type}{rulebase}Rules?location=device-group&'
                f'device-group={device_group}&name={rule_name}'
            )
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'

        rule = self.get_rule(rule_name, rule_type, rulebase, device_group)

        # NAT RULE LOGIC
        if rule_type.lower() == 'nat':

            if translation_type:
                if translation_type == 'static-ip':
                    # Unable to remove static ip as you cannot have none. Raising Exception
                    raise EmptySourceTranslationForRule(
                        description=("Unable to remove address object from rule"
                                     "due to it is the last object in rule. "
                                     "Please, delete the rule."),
                        last_object=address_name,

                        rule_name=rule_name,
                        rule_type=rule_type,
                        rulebase=rulebase,

                        device_group=device_group,

                        direction=direction,
                        translation_type=translation_type,
                        translation_direction=translation_direction
                                                        )
            else:
                rule[direction]['member'].remove(address_name)

                if len(rule[direction]['member']) == 0:
                    raise EmptyDirectionForRule(
                        description=("Unable to remove address object from "
                                     "rule due to it is the last object in rule. "
                                     "Please, delete the rule."),
                        last_object=address_name,

                        rule_name=rule_name,

                        rule_type=rule_type,
                        rulebase=rulebase,

                        device_group=device_group,

                        direction=direction
                                                )
                payload = {'entry': [rule]}

                resp = self._put_req(self.rest_uri+uri, payload)

                return resp.json()

        elif rule_type.lower() == 'security':
            # Security Rule Logic

            rule[direction]['member'].remove(address_name)

            if len(rule[direction]['member']) == 0:
                raise EmptyDirectionForRule(
                    description=("Unable to remove address object from rule "
                                 "due to it is the last object in rule. "
                                 "Please, delete the rule."),
                    last_object=address_name,

                    rule_name=rule_name,

                    rule_type=rule_type,
                    rulebase=rulebase,

                    device_group=device_group,

                    direction=direction
                                            )

            payload = {'entry': [rule]}

            resp = self._put_req(self.rest_uri+uri, payload)

            return resp.json()

    def remove_addressgroup_from_rule(self, address_group, rule_name, rule_type, rulebase,
                                      device_group, direction, force=False):
        if not type(rulebase) is str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")

        if device_group.lower() != "shared":
            uri = ('Policies/' + rule_type + rulebase + 'Rules?location=device-group&device-group='
                   + device_group + '&name=' + rule_name)
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'

        rule = self.get_rule(rule_name, rule_type, rulebase, device_group)
        rule[direction]['member'].remove(address_group)

        if len(rule[direction]['member']) == 0:
            raise EmptyDirectionForRule(
                description=("Unable to remove address object from rule "
                             "due to it is the last rule. Please, delete the rule."),
                last_object=address_group,

                rule_name=rule_name,

                rule_type=rule_type,
                rulebase=rulebase,

                device_group=device_group,

                direction=direction)

        payload = {'entry': [rule]}

        resp = self._put_req(self.rest_uri+uri, payload)

        return resp.json()

    def remove_address_from_addressgroup(self, address_name, address_group_name, device_group):

        if device_group.lower() != "shared":
            uri = ('Objects/AddressGroups?location=device-group&device-group='
                   + f'{device_group}&name={address_group_name}')
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={address_group_name}'

        address_group = self.get_addressgroup(address_group_name, device_group)

        if len(address_group['static']['member']) == 1:

            # resp = self.delete_address_group(address_group_name, device_group)
            raise EmptyAddressGroup(
                description=(f"Unable to remove address {address_name} due to it being the last "
                             "object in the group. You must delete the group."),
                address_group=address_group_name,

                device_group=device_group
                )

        address_group['static']['member'].remove(address_name)

        payload = {'entry': [address_group]}

        resp = self._put_req(self.rest_uri+uri, payload)

        if resp.status_code == 200:
            return resp.json()

        return resp.json()

    def delete_rule(self, rule_name, rule_type, rulebase, device_group):

        if device_group.lower() != "shared":
            uri = ('Policies/' + rule_type + rulebase + 'Rules?location=device-group&device-group='
                   + device_group + '&name=' + rule_name)
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'

        resp = self._del_req(self.rest_uri+uri)

        return DeletionResponse(requests_resp=resp, object=rule_name)

    def get_rule(self, rule_name, rule_type, rulebase, device_group):

        # NOTE: For some reason rule comes back as an array, removed arrary on return

        if device_group.lower() != "shared":
            uri = ('Policies/' + rule_type + rulebase + 'Rules?location=device-group&device-group='
                   + device_group + '&name=' + rule_name)
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and "@total-count" in resp.json()['result'] and \
                int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple rules detected for rule '{rule_name}' "
                            f"in Device Group '{device_group}'")

        elif resp.ok and "@total-count" in resp.json()['result'] and \
                resp.json()['result']['@total-count'] == "0":
            return []  # empty

        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]

        return resp.json()

    def create_rule(self, name, rule_type, rulebase, device_group, source, destination, action,
                    service="any", application="any", _from="any", _to="any"):
        if action not in ["deny", "allow", "drop", "reset-client", "reset-server", "reset-both"]:
            raise ValueError('"action" parameter must be one of the following: "deny", "allow", '
                             '"drop", "reset-client", "reset-server", "reset-both"')

        if rule_type.lower() != "security":
            raise ValueError("This method only supports Security rules at the moment")

        if device_group.lower() != "shared":
            uri = (f'Policies/{rule_type}{rulebase}Rules?location='
                   'device-group&device-group={device_group}&name={name}')
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={name}'

        payload = {
            "entry": {
                "@name": name,
                "from": {
                    "member": _from if isinstance(_from, list) else [_from]
                        },
                "to": {
                    "member": _to if isinstance(_to, list) else [_to]
                        },
                "source": {
                    "member": source if isinstance(source, list) else [source]
                        },
                "destination": {
                    "member": destination if isinstance(destination, list) else [destination]
                        },
                "service": {
                    "member": service if isinstance(service, list) else [service]
                        },
                "application": {
                    "member": application if isinstance(application, list) else [application]
                        },
                "action": action
            }
        }
        resp = self._post_req(self.rest_uri+uri, payload)

        return resp.json()

    def remove_reference_from_object(self, reference, object_name, device_group, force=False):

        if "rulebase -> security -> rules ->" in reference:
            direction = ""  # source or destination
            rulebase = ""  # pre, post, or default
            rule_type = "Security"

            if "post-rulebase -> security -> rules ->" in reference:
                rulebase = "post"
            elif "pre-rulebase -> security -> rules ->" in reference:
                rulebase = "pre"
            elif "default-rulebase -> security -> rules ->" in reference:
                rulebase = "default"
            else:
                raise Exception(f"Unable to determine rulebase for reference: {reference}")

            r = re.match(f"{rulebase}-rulebase -> security -> rules -> (.*\.$)", reference)
            rule_name_reg = re.search("(.*) -> source\.", r.group(1))
            if not rule_name_reg:
                rule_name_reg = re.search("(.*) -> destination\.", r.group(1))
                if not rule_name_reg:
                    raise Exception(f"Unable to determine rule_name for reference {reference}")
                else:
                    rule_name = rule_name_reg.group(1)
                    direction = "destination"
            else:
                rule_name = rule_name_reg.group(1)

                direction = "source"

            resp = self.remove_address_from_rule(address_name=object_name,
                                                 rule_name=rule_name,
                                                 rule_type=rule_type,
                                                 rulebase=rulebase,
                                                 device_group=device_group,
                                                 direction=direction)
            if '@status' in resp and resp['@status'] == "success":
                self.logger.info(f"Removed address {object_name} from rule {rule_name} "
                                 f"in DG {device_group}")

            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")

        elif "rulebase -> nat -> rules ->" in reference:
            direction = ""  # source or destination
            rulebase = ""  # pre, post, or default
            rule_type = "NAT"
            translation_direction = None
            translation_type = None

            if "post-rulebase -> nat -> rules ->" in reference:
                rulebase = "post"
            elif "pre-rulebase -> nat -> rules ->" in reference:
                rulebase = "pre"
            elif "default-rulebase -> nat -> rules ->" in reference:
                rulebase = "default"
            else:
                raise Exception(f"Unable to determine rulebase for reference: {reference}")

            r = re.match(f"{rulebase}-rulebase -> nat -> rules -> (.*\.$)", reference)

            # With NAT Rules you have source and destination
            #  and also translated source & translated destination.
            # The next part of code determines which is referenced

            if (' -> source-translation -> ' in r.group(1)) or \
               (' -> destination-translation -> ' in r.group(1)):

                rule_name_reg = re.search("(.*) -> source-translation -> ", r.group(1))

                if not rule_name_reg:
                    rule_name_reg = re.search("(.*) -> destination-translation -> ", r.group(1))
                    if not rule_name_reg:
                        raise Exception(f"Unable to determine rule_name for reference {reference}")
                    else:
                        rule_name = rule_name_reg.group(1)
                        translation_direction = "destination-translation"

                else:
                    rule_name = rule_name_reg.group(1)

                    translation_direction = "source-translation"

                translation_type_reg = re.search(
                    f" -> {translation_direction} -> ((.*) -> )",
                    r.group(1)
                )
                if not translation_type_reg:
                    raise Exception("Unable to determine translation type "
                                    f"(ex. static, dynamic, etc.) for reference {reference}")
                translation_type = translation_type_reg.group(2)

            else:
                r = re.match(f"{rulebase}-rulebase -> nat -> rules -> (.*\.$)", reference)
                rule_name_reg = re.search("(.*) -> source\\.", r.group(1))
                if not rule_name_reg:
                    rule_name_reg = re.search("(.*) -> destination\\.", r.group(1))
                    if not rule_name_reg:
                        raise Exception(f"Unable to determine rule_name for reference {reference}")
                    else:
                        rule_name = rule_name_reg.group(1)
                        direction = "destination"
                else:
                    rule_name = rule_name_reg.group(1)

                    direction = "source"

            if translation_direction and translation_type:
                resp = self.remove_address_from_rule(address_name=object_name,
                                                     rule_name=rule_name,
                                                     rule_type=rule_type,
                                                     rulebase=rulebase,
                                                     device_group=device_group,
                                                     direction=direction,
                                                     translation_type=translation_type,
                                                     translation_direction=translation_direction)
            else:
                resp = self.remove_address_from_rule(address_name=object_name,
                                                     rule_name=rule_name,
                                                     rule_type=rule_type,
                                                     rulebase=rulebase,
                                                     device_group=device_group,
                                                     direction=direction)

            if '@status' in resp and resp['@status'] == "success":
                self.logger.info(f"Removed address {object_name} from rule {rule_name} "
                                 f"in DG {device_group}")

            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")

        elif 'address-group -> ' in reference:
            r = re.match('^address-group -> (.*?) -> static', reference)
            address_group = r.group(1)

            resp = self.remove_address_from_addressgroup(object_name, address_group, device_group)
            if '@status' in resp and resp['@status'] == "success":
                self.logger.info(f"Removed address {object_name} from address group {address_group}")

        else:
            raise Exception(f"Unable to delete object {object_name} \n"
                            f"Referenced object type not supported for deletion:  {reference}'")

    def _filter_and_remove_obj_references(self,
                                          json_resp_from_failure_to_remove_delete_item,
                                          obj_name, device_group, force=False):

        referenced_groups_deleted = []
        referenced_rules_deleted = []

        # If object can't be deleted because of references, this will delete refs

        first_ref_has_not_been_deleted = True
        while first_ref_has_not_been_deleted:

            resp = json_resp_from_failure_to_remove_delete_item
            if resp['message'].lower() == "reference not zero" and "details" in resp:
                self.logger.info(f"Found References for object {obj_name}. "
                                 "Remove object from References...")

                for detail in resp['details']:
                    if "@type" in detail and detail['@type'].lower() == "causeinfo":
                        for cause in detail['causes']:
                            if (f"{obj_name} cannot be deleted because of ""references from:") \
                                  in cause["description"]:
                                references = self._convert_reference_response_to_list(
                                             cause["description"])
                self.logger.info(f"References:  {references}")

                for reference in references:
                    try:

                        self.remove_reference_from_object(reference['reference'],
                                                          object_name=obj_name,
                                                          device_group=reference["device-group"])

                    except EmptyDirectionForRule as e:

                        if force:
                            resp = self.delete_rule(
                                rule_name=e.rule_name,
                                rule_type=e.rule_type,
                                rulebase=e.rulebase,
                                device_group=e.device_group
                            )
                            referenced_groups_deleted = (
                                referenced_groups_deleted + resp.referenced_groups_deleted
                                if resp.referenced_groups_deleted
                                else referenced_groups_deleted
                            )
                            referenced_rules_deleted = (
                                referenced_rules_deleted + resp.referenced_rules_deleted
                                if resp.referenced_rules_deleted
                                else referenced_rules_deleted
                            )
                            referenced_rules_deleted.append(e.rule_name)
                            self.logger.info(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e

                    except EmptyAddressGroup as e:
                        if force:
                            resp = self.delete_address_group(
                                address_group=e.address_group,
                                device_group=e.device_group,
                                force=force
                            )
                            referenced_groups_deleted = (
                                referenced_groups_deleted + resp.referenced_groups_deleted
                                if resp.referenced_groups_deleted
                                else referenced_groups_deleted
                            )
                            referenced_rules_deleted = (
                                referenced_rules_deleted + resp.referenced_rules_deleted
                                if resp.referenced_rules_deleted
                                else referenced_rules_deleted
                            )
                            referenced_groups_deleted.append(e.address_group)
                            self.logger.info(f"Deleted reference: Address Group {e.address_group}")
                        else:
                            raise e

                    except EmptySourceTranslationForRule as e:

                        if force:
                            resp = self.delete_rule(
                                rule_name=e.rule_name,
                                rule_type=e.rule_type,
                                rulebase=e.rulebase,
                                device_group=e.device_group
                            )
                            referenced_groups_deleted = (
                                referenced_groups_deleted + resp.referenced_groups_deleted
                                if resp.referenced_groups_deleted
                                else referenced_groups_deleted
                            )
                            referenced_rules_deleted = (
                                referenced_rules_deleted + resp.referenced_rules_deleted
                                if resp.referenced_rules_deleted
                                else referenced_rules_deleted
                            )
                            referenced_rules_deleted.append(e.rule_name)
                            self.logger.info(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e

            first_ref_has_not_been_deleted = False

        return DeletionResponse(
            requests_resp=None,
            referenced_groups_deleted=referenced_groups_deleted,
            referenced_rules_deleted=referenced_rules_deleted
        )

    @staticmethod
    def find_lowest_available_number(numbers):

        ''' used in create_vsys method '''
        # Convert the strings to integers
        numbers = [int(num) for num in numbers]

        for i in range(1, 100):
            if i not in numbers:
                return i

    def auto_vsysid(self, serial, devices=None):
        ''' automatically finds the next lowest vsys id available to use,
            this is used with create_vsys method
            '''
        if devices is None:
            devices = self.get_devices()
        vsys_ids_used = []

        for device in devices:
            if device['serial'] == serial:
                if 'vsys' in device:
                    for dev_vsys in device['vsys']['entry']:
                        dev_vsys_id = dev_vsys['@name'][-1]
                        vsys_ids_used.append(dev_vsys_id)

        return PanoramaAPI.find_lowest_available_number(vsys_ids_used)

    def create_vsys(self, vsys_name: str,
                    vsys_id: str,
                    serial: int,
                    tag_name: str = None,
                    make_changes_on_active_ha_peer: bool = False):

        '''
        set vsys_id to 'auto' to automatically find the next available vsys id

        make_changes_on_active_ha_peer; will verify sn is an active peer if HA,
        else will create vsys on active peer

        '''

        # serial = serial.split('_')[0]
        self.logger.info(f"Creating vsys {vsys_name} with id {vsys_id} on device {serial}")
        if str(vsys_id).lower() == 'auto':
            # find next available vsys id automatically
            vsys_id = self.auto_vsysid(serial)
        # FIXME: FINISH BELOW FOR CONFIGURING PEER
        # if make_changes_on_active_ha_peer:

        #     devices = self.get_devices()
        #     found_active_peer = False
        #     peer_index = -1

        #     while not found_active_peer and peer_index < 2:
        #         peer_index += 1

        #         for device in devices:

        #             if device['@name'] == sn.split('_')[peer_index]:
        #                 if 'ha' in device:
        #                     if device['ha']['state'] == 'active':
        #                         found_active_peer = True
        #                         serial = device['@name']

        # TODO: WRITE LOGIC TO FIND OUT IF DEVICE IS ACTIVE OR PASSIVE

        ''' Payload could also containt colors and comments:
                                    <tag>
                                        <color>color15</color>
                                        <comments>"other date created"</comments>

                                    </tag>
        '''
        if tag_name:
            payload = (
                f'''
                <entry name="vsys{vsys_id}">
                    <display-name>{vsys_name}</display-name>
                    <tag>
                        <entry name="{tag_name}"></entry>
                        <entry name="RESDATE:{self.today}"></entry>
                    </tag>
                </entry>
                '''
            )
        else:
            payload = f'''
                        <entry name="vsys{vsys_id}">
                            <display-name>{vsys_name}</display-name>

                        </entry>
                        '''
        # FIXME: add date created

        uri = (f'?type=config&target={serial}&action=set'
               f'&xpath=/config/devices/entry/vsys&element={payload}')
        try:
            resp = self._get_req(self.xml_uri+uri)
            resp.raise_for_status()

        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTPError creating vsys: {e}")
            raise Exception(f"HTTPError creating vsys: {e}")
        except Exception as e:
            self.logger.error(f"Error creating vsys: {e}")
            raise Exception(f"Error creating vsys: {e}")
        return self.xml_to_json(resp)['response']

    def delete_vsys(self, serial: int, vsys_name: str = None, vsys_id: int = None, ):

        '''
        Deletes vysys. Requires serial and either vsys_name or
        vsys_id to be passed. If both are passed, vsys_id will be used.

        '''

        if vsys_id:
            uri = (f"?type=config&target={serial}&action=delete"
                   f"&xpath=/config/devices/entry/vsys/entry[@name='vsys{vsys_id}']"
                   )
        elif vsys_name:
            uri = (f"?type=config&target={serial}&action=delete"
                   f"&xpath=/config/devices/entry/vsys/entry[@name='{vsys_name}']")
        else:
            raise ValueError("Must pass either vsys_name or vsys_id to delete vsys")

        resp = self._post_req(self.xml_uri+uri)
        self.logger.info(f"Deleted vsys {vsys_name} on device {serial} "
                         f"with response: {self.xml_to_json(resp)['response']}")

        return self.xml_to_json(resp)['response']

    def decommission_server(self, servers_to_decommission):

        # address_objects_to_delete = []
        found_obj = False
        del_response_objects = []

        if type(servers_to_decommission) is str:
            servers_to_decommission = [servers_to_decommission]

        device_groups = self.get_devicegroups(include_shared=True)

        if type(device_groups) is dict and 'message' in device_groups.keys() and \
                                           'invalid cred' in device_groups['message'].lower():
            raise Exception("Invalid credentials for Panorama")

        for decomm_server in servers_to_decommission:
            for dg in device_groups:

                # query all addresses and loop through to find all addresses
                addresses = self.get_addresses(dg['@name'])
                for address in addresses:
                    if ('ip-netmask' in address and
                        f"{decomm_server}/32" == address['ip-netmask']) or \
                       ('ip-netmask' in address and f"{decomm_server}" == address['ip-netmask']):
                        # The following logic is to detect duplicate findings from an address being
                        # in a device group but shared into another, only need to delete 1 time
                        if '@loc' in address and address['@loc'] != address['@device-group']:
                            continue
                        elif '@loc' in address and address['@loc'] == address['@device-group'] or \
                             '@loc' not in address and '@device-group' in address or \
                             '@location' in address and address['@location'] == "shared":
                            self.logger.info((f"\nDeleting {address['@name']}"
                                              f" from {dg['@name']}...\n"))
                            del_resp = self.delete_address(address['@name'], dg['@name'], force=True)

                            self.logger.info(f"Deleted {address['@name']} from {dg['@name']}...\n\n")
                            del_response_objects.append(del_resp)
                            found_obj = True

                        else:
                            raise Exception((f"Unable to remove address {address['@name']} "
                                             f"in Device Group {dg['@name']}. \nRef"))

            if not found_obj:
                self.logger.info("No addresses found!")  # FIXME:
                # should probably raise to make pipeline fail? Will decide later

            return del_response_objects


class PanOSAPI(_PanPaloShared):

    rest_uri = "/restapi/v10.2/"
    xml_uri = "/api/"

    '''
    api class for Palo Alto Firewall bypassing Panorama

    '''

    def __init__(self, panorama_mgmt_ip):
        super().__init__()
        self.IP = panorama_mgmt_ip
        self.LoggedIn = False
        self.vsys = "vsys1"

    @staticmethod
    def _convert_reference_response_to_list(references_string):
        """
        This is used when trying to delete an object, but the response from
        API call is that the object is referenced in other places
        like rules or groups.

        This will take the string of that gives where the
        references are located and converts it to a list

        This is needed because the references come back in one big string
        """
        # validate it is a reference
        if "cannot be deleted because of references from:" not in references_string:
            raise ValueError("Did not pass a string that is a Palo Alto reference as an argument")

        references = []
        # _shared = None
        references_string_split = re.split(r'(?<=\.  )', references_string)

        if references_string_split:

            for i in references_string_split:
                if "cannot be deleted because of references from:" not in i:
                    ref = {}
                    ref['reference'] = i
                    references.append(ref)

        else:
            raise Exception(f"Unable to split reference string: {references_string} ")

        return references

    def get_api_version(self):
        uri = f"?type=version&key={self.headers['X-PAN-Key']}"
        resp = self._get_req(self.xml_uri+uri)
        responseXml = ET.fromstring(resp.content)
        return responseXml.find('result').find('sw-version').text
        # return {"status": responseXml.find('result').find('job').find('status').text,

    def get_sec_rules(self, location="vsys"):

        if location == "vsys":
            uri = f'Policies/SecurityRules?location={location}&{location}={self.vsys}'
        else:
            uri = f'Policies/SecurityRules?location={location}'

        resp = self._get_req(self.rest_uri+uri)

        return resp.json()

    def get_addresses(self, location="vsys"):

        if location == "vsys":
            uri = f'Objects/Addresses?location={location}&{location}={self.vsys}'
        else:
            uri = f'Objects/Addresses?location={location}'

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry']
        elif (resp.ok and
              "@total-count" in resp.json()['result'] and 
              resp.json()['result']['@total-count'] == "0"):
            return []  # empty
        return resp

    def get_tags(self, location: str = None):
        uri = 'objects/tags'
        resp = self._get_req(self.rest_uri+uri)
        if resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry']
        elif resp.ok and "@total-count" in resp.json()['result'] and \
                resp.json()['result']['@total-count'] == "0":
            return []  # empty
        return resp

    def create_address(self, name, ip_netmask, description="", location="vsys"):
        if location == "vsys":
            uri = f'Objects/Addresses?location={location}&{location}={self.vsys}&name={name}'
        else:
            uri = f'Objects/Addresses?location={location}&name={name}'

        payload = {
            "entry": {
                "ip-netmask": ip_netmask,
                "@name": name,
                "description": description
            }
        }

        resp = self._post_req(self.rest_uri+uri, payload)

        return resp.json()

    def get_addressgroup(self, address_group, location="vsys"):

        if location == "vsys":
            uri = (
                f'Objects/AddressGroups?location={location}&{location}={self.vsys}'
                f'&name={address_group}'
            )
        else:
            uri = f'Objects/AddressGroups?location={location}&name={address_group}'

        resp = self._get_req(self.rest_uri+uri)

        if (resp.ok and
            "@total-count" in resp.json()['result'] and
                int(resp.json()['result']['@total-count']) > 1):
            raise Exception(f"Multiple address groups detected for address group '{address_group}'")

        elif (resp.ok and
              "@total-count" in resp.json()['result'] and 
              resp.json()['result']['@total-count'] == "0"):
            return [] # empty

        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]

    def create_address_group(self, name, members=[], description="", location="vsys"):

        if location == "vsys":
            uri = f'Objects/AddressGroups?location={location}&{location}={self.vsys}&name={name}'
        else:
            uri = f'Objects/AddressGroups?location={location}&name={name}'

        payload = {
            "entry": {
                "static": {"member": members if isinstance(members, list) else [members]},
                "@name": name,
                "description": description
            }
        }

        resp = self._post_req(self.rest_uri+uri, payload)

        return resp.json()

    def delete_address_group(self,
                             address_group,
                             location="vsys",
                             force=False,
                             force_deletion_of_all_objects_referenced=None):

        '''
        params;
        force: This will remove direct references 
        (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: This will do the same as force
        AND will remove references of references, etc.

        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced
        to same value. To have different values, set them both manually !!!!!
        '''

        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")

        if force_deletion_of_all_objects_referenced == None:
            force_deletion_of_all_objects_referenced = force

        if location == "vsys":
            uri = f'Objects/AddressGroups?location={location}&{location}={self.vsys}&name={address_group}'
        else:
            uri = f'Objects/AddressGroups?location={location}&name={address_group}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return DeletionResponse(requests_resp=resp,
                                    referenced_groups_deleted=None,
                                    referenced_rules_deleted=None,
                                    object=address_group)

        if "@status" in resp.json().keys() and resp.json()['@status'] == 'success':
            return DeletionResponse(requests_resp=resp,
                                    referenced_groups_deleted=None,
                                    referenced_rules_deleted=None,
                                    object=address_group)

            # If object can't be deleted because of references,
            # this will delete refs if force switch == True

        reference_remove_resp = self._filter_and_remove_obj_references(resp.json(),
                                                                       address_group,
                                                                       force=force)

        # self._delete_refs_of_refs(resp.json())

        resp2 = self._del_req(self.rest_uri+uri)
        self.logger.info(f"Deleted references. Now deleting address group {address_group} object.\n")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            self.logger.info(f"Deleted address group object {address_group}")
            return DeletionResponse(requests_resp=resp2,
                                    referenced_groups_deleted=reference_remove_resp.referenced_groups_deleted,
                                    referenced_rules_deleted=reference_remove_resp.referenced_rules_deleted,
                                    object=address_group)

        else:
            try:
                raise Exception(f"Unable to delete object '{address_group}'. \n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_group}'.")

    def delete_address(self,
                       address_name,
                       location="vsys",
                       force=False,
                       force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references
        (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced:
        This will do the same as force AND will remove references of references, etc.

        !!!!! WARNING: setting force will ALSO set 
        force_deletion_of_all_objects_referenced to same value.
        To have different values, set them both manually !!!!!
        '''
        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")

        if force_deletion_of_all_objects_referenced is None:
            force_deletion_of_all_objects_referenced = force

        if location == "vsys":
            uri = f'Objects/Addresses?location={location}&{location}={self.vsys}&name={address_name}'
        else:
            uri = f'Objects/Addresses?location={location}&name={address_name}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return DeletionResponse(requests_resp=resp,
                                    referenced_groups_deleted=None,
                                    referenced_rules_deleted=None,
                                    object=address_name)
            # return resp.json()

        if "@status" in resp.json() and resp.json()['@status'] == 'success':
            return DeletionResponse(requests_resp=resp,
                                    referenced_groups_deleted=None,
                                    referenced_rules_deleted=None,
                                    object=address_name)

        # If object can't be deleted because of references, this will delete refs if force switch == True

        reference_remove_resp = self._filter_and_remove_obj_references(resp.json(), address_name, force=force)

        resp2 = self._del_req(self.rest_uri+uri)

        self.logger.info(f"Deleted references. Now deleting address object {address_name}.")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            self.logger.info(f"Deleted address object {address_name}")
            return DeletionResponse(requests_resp=resp2, referenced_groups_deleted=reference_remove_resp.referenced_groups_deleted, referenced_rules_deleted=reference_remove_resp.referenced_rules_deleted, object=address_name)

        else:
            try:
                raise Exception(f"Unable to delete object '{address_name}'. \n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_name}'.")

    def remove_address_from_rule(self, address_name, rule_name, rule_type, direction, force=False, translation_direction=None, translation_type=None, location="vsys"):

        if location == "vsys":
            uri = f'Policies/{rule_type}Rules?location={location}&{location}={self.vsys}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}Rules?location={location}&name={rule_name}'

        rule = self.get_rule(rule_name, rule_type, location)

        # NAT RULE LOGIC
        if rule_type.lower() == 'nat':

            if translation_type:
                if translation_type == 'static-ip':
                    # Unable to remove static ip as you cannot have none. Raising Exception
                    raise EmptySourceTranslationForRule(
                        description="Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                        last_object=address_name,

                        rule_name=rule_name,
                        rule_type=rule_type,
                        location= location,

                        direction=direction,
                        translation_type=translation_type,
                        translation_directio=translation_direction
                                                        )
            else:
                rule[direction]['member'].remove(address_name)

                if len(rule[direction]['member']) == 0:
                    raise EmptyDirectionForRule(
                        description="Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                        last_object=address_name,

                        rule_name=rule_name,

                        rule_type=rule_type,
                        location=location,

                        direction=direction
                                                )
                payload = {'entry': [rule]}

                resp = self._put_req(self.rest_uri+uri, payload)

                return resp.json()

        elif rule_type.lower() == 'security':
        # Security Rule Logic

            rule[direction]['member'].remove(address_name)

            if len(rule[direction]['member']) == 0:
                raise EmptyDirectionForRule(
                    description="Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                    last_object=address_name,

                    rule_name=rule_name,

                    rule_type=rule_type,
                    location=location,

                    direction=direction
                                            )

            payload = {'entry': [rule]}

            resp = self._put_req(self.rest_uri+uri, payload)

            return resp.json()

    def remove_addressgroup_from_rule(self, address_group, rule_name, rule_type, rulebase, direction, force=False, location="vsys"):
        if not type(rulebase) == str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")

        if location == "vsys":
            uri = f'Policies/{rule_type}{rulebase}Rules?location={location}&{location}={self.vsys}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={location}&name={rule_name}'

        rule = self.get_rule(rule_name, rule_type, rulebase, location="vsys")
        rule[direction]['member'].remove(address_group)

        if len(rule[direction]['member']) == 0:
            raise EmptyDirectionForRule(
                description="Unable to remove address object from rule due to it is the last rule. Please, delete the rule.",
                last_object=address_group,

                rule_name=rule_name,

                rule_type=rule_type,
                rulebase=rulebase,

                location=location,

                direction=direction)

        payload = {'entry': [rule]}

        resp = self._put_req(self.rest_uri+uri, payload)

        return resp.json()

    def remove_address_from_addressgroup(self, address_name, address_group_name, location="vsys"):

        if location == "vsys":
            uri = f'Objects/AddressGroups?location={location}&{location}={self.vsys}&name={address_group_name}'
        else:
            uri = f'Objects/AddressGroups?location={location}&name={address_group_name}'

        address_group = self.get_addressgroup(address_group_name, location)

        del address_group['@location']
        del address_group['@vsys']
        if len(address_group['static']['member']) == 1:

            # resp = self.delete_address_group(address_group_name, device_group)
            raise EmptyAddressGroup(
                description= f"Unable to remove address {address_name} due to it being the last object in the group. You must delete the group.",
                address_group=address_group_name,

                location=location
                )

        address_group['static']['member'].remove(address_name)

        payload = {'entry': [address_group]}

        resp = self._put_req(self.rest_uri+uri, payload)
        if resp.status_code == 200:
            return resp.json()

        return resp.json()

    def delete_rule(self, rule_name, rule_type, location):

        if location == "vsys":
            uri = f'Policies/{rule_type}Rules?location={location}&{location}={self.vsys}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}Rules?location={location}&name={rule_name}'

        resp = self._del_req(self.rest_uri+uri)

        return DeletionResponse(requests_resp=resp, object=rule_name)

    def get_rule(self, rule_name, rule_type, location):

        # NOTE: For some reason rule comes back as an array, removed arrary on return

        if location == "vsys":
            uri = f'Policies/{rule_type}Rules?location={location}&{location}={self.vsys}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}Rules?location={location}&name={rule_name}'

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and "@total-count" in resp.json()['result'] and int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple rules detected for rule '{rule_name}'")

        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return []  # empty

        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]

        return resp.json()

    def create_rule(self, name, rule_type, source, destination, action, service="any", application="any", _from="any", _to="any", location="vsys"):

        if action not in ["deny", "allow", "drop", "reset-client", "reset-server", "reset-both"]:
            raise ValueError('"action" parameter must be one of the following: "deny" "allow" "drop" "reset-client" "reset-server" "reset-both"')

        if rule_type.lower() != "security":
            raise ValueError("This method only supports Security rules at the moment")

        if location == "vsys":
            uri = f'Policies/{rule_type}Rules?location={location}&{location}={self.vsys}&name={name}'
        else:
            uri = f'Policies/{rule_type}Rules?location={location}&name={name}'

        payload = {
            "entry": {
                "@name": name,
                "from": {
                    "member": _from if isinstance(_from, list) else [_from]
                        },
                "to": {
                    "member": _to if isinstance(_to, list) else [_to]
                        },
                "source": {
                    "member": source if isinstance(source, list) else [source]
                        },
                "destination": {
                    "member": destination if isinstance(destination, list) else [destination]
                        },
                "service": {
                    "member": service if isinstance(service, list) else [service]
                        },
                "application": {
                    "member": application if isinstance(application, list) else [application]
                        },
                "action": action
            }
        }
        resp = self._post_req(self.rest_uri+uri, payload)

        return resp.json()

    def remove_reference_from_object(self, reference, object_name, location="vsys", force=False):

        if "rulebase -> security -> rules ->" in reference:
            direction = ""  # source or destination
            # rulebase = "" # pre, post, or default
            rule_type = "Security"

        # raise Exception(f"Unable to determine rulebase for reference: {reference}")

            r = re.match(f"rulebase -> security -> rules -> (.*\.$)", reference)
            rule_name_reg = re.search("(.*) -> source\.", r.group(1))
            if not rule_name_reg:
                rule_name_reg = re.search("(.*) -> destination\.", r.group(1))
                if not rule_name_reg:
                    raise Exception(f"Unable to determine rule_name for reference {reference}")
                else:
                    rule_name = rule_name_reg.group(1)
                    direction = "destination"
            else:
                rule_name = rule_name_reg.group(1)

                direction = "source"

            resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type,

                                             location=location, direction=direction)
            if '@status' in resp and resp['@status'] == "success":

                self.logger.info(f"Removed address object_name from rule {rule_name}")

            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")

        elif "rulebase -> nat -> rules ->" in reference:
            direction = ""  # source or destination
            rule_type = "NAT"
            translation_direction = None
            translation_type = None

            r = re.match(f"rulebase -> nat -> rules -> (.*\.$)", reference)

            # With NAT Rules you have source and destination and also translated source & translated destination.
            # The next part of code determines which is referenced

            if ' -> source-translation -> ' in r.group(1) or ' -> destination-translation -> ' in r.group(1):

                rule_name_reg = re.search("(.*) -> source-translation -> ", r.group(1))

                if not rule_name_reg:
                    rule_name_reg = re.search("(.*) -> destination-translation -> ", r.group(1))
                    if not rule_name_reg:
                        raise Exception(f"Unable to determine rule_name for reference {reference}")
                    else:
                        rule_name = rule_name_reg.group(1)
                        translation_direction = "destination-translation"

                else:
                    rule_name = rule_name_reg.group(1)

                    translation_direction = "source-translation"

                translation_type_reg = re.search(f" -> {translation_direction} -> ((.*) -> )", r.group(1))
                if not translation_type_reg:
                    raise Exception(f"Unable to determine translation type (ex. static, dynamic, etc.) for reference {reference}")
                translation_type = translation_type_reg.group(2)

            else:
                r = re.match(f"rulebase -> nat -> rules -> (.*\.$)", reference)
                rule_name_reg = re.search("(.*) -> source\.", r.group(1))
                if not rule_name_reg:
                    rule_name_reg = re.search("(.*) -> destination\.", r.group(1))
                    if not rule_name_reg:
                        raise Exception(f"Unable to determine rule_name for reference {reference}")
                    else:
                        rule_name = rule_name_reg.group(1)
                        direction = "destination"
                else:
                    rule_name = rule_name_reg.group(1)

                    direction = "source"

            if translation_direction and translation_type:
                resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type,

                                             direction=direction, translation_type=translation_type, translation_direction=translation_direction)
            else:
                resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type,

                                             direction=direction)

            if '@status' in resp and resp['@status'] == "success":

                self.logger.info(f"Removed address object_name from rule {rule_name}")

            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")

        elif 'address-group -> ' in reference:
            r = re.match('^address-group -> (.*?) -> static', reference)
            address_group = r.group(1)

            resp = self.remove_address_from_addressgroup(object_name, address_group)
            if '@status' in resp and resp['@status'] == "success":

                self.logger.info(f"Removed address {object_name} from address group {address_group}")

        else:
            raise Exception(f"Unable to delete object {object_name} \nReferenced object type not supported for deletion:  {reference}'")

    def _filter_and_remove_obj_references(self, json_resp_from_failure_to_remove_delete_item, obj_name, force=False):

        referenced_groups_deleted = []
        referenced_rules_deleted = []

         # If object can't be deleted because of references, this will delete refs
        first_ref_has_not_been_deleted = True
        while first_ref_has_not_been_deleted:

            resp = json_resp_from_failure_to_remove_delete_item
            if resp['message'].lower() == "reference not zero" and "details" in resp:
                self.logger.info(f"Found References for object {obj_name}. Remove object from References...")

                for detail in resp['details']:
                    if "@type" in detail and detail['@type'].lower() == "causeinfo":
                        for cause in detail['causes']:
                            if f"{obj_name} cannot be deleted because of references from:" in cause["description"]:
                                references = self._convert_reference_response_to_list(cause["description"])

                for reference in references:
                    try:
                        self.remove_reference_from_object(reference['reference'], object_name=obj_name)

                    except EmptyDirectionForRule as e:

                        if force:
                            resp = self.delete_rule(rule_name=e.rule_name, rule_type=e.rule_type, location=e.location)
                            referenced_groups_deleted = referenced_groups_deleted + resp.referenced_groups_deleted if resp.referenced_groups_deleted else referenced_groups_deleted
                            referenced_rules_deleted = referenced_rules_deleted + resp.referenced_rules_deleted if resp.referenced_rules_deleted else referenced_rules_deleted
                            referenced_rules_deleted.append(e.rule_name)
                            self.logger.info(f"Deleted reference: Rule {e.rule_name}")

                        else:
                            raise e

                    except EmptyAddressGroup as e:
                        if force:
                            resp = self.delete_address_group(address_group=e.address_group, location=e.location, force=force)
                            referenced_groups_deleted = referenced_groups_deleted + resp.referenced_groups_deleted if resp.referenced_groups_deleted else referenced_groups_deleted
                            referenced_rules_deleted = referenced_rules_deleted + resp.referenced_rules_deleted if resp.referenced_rules_deleted else referenced_rules_deleted
                            referenced_groups_deleted.append(e.address_group)
                            self.logger.info(f"Deleted reference: Address Group {e.address_group}")
                        else:
                            raise e

                    except EmptySourceTranslationForRule as e:

                        if force:
                            self.delete_rule(rule_name=e.rule_name, rule_type=e.rule_type, location=e.location)
                            referenced_groups_deleted = referenced_groups_deleted + resp.referenced_groups_deleted if resp.referenced_groups_deleted else referenced_groups_deleted
                            referenced_rules_deleted = referenced_rules_deleted + resp.referenced_rules_deleted if resp.referenced_rules_deleted else referenced_rules_deleted
                            referenced_rules_deleted.append(e.rule_name)
                            self.logger.info(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e

            first_ref_has_not_been_deleted = False

        return DeletionResponse(requests_resp=None, referenced_groups_deleted=referenced_groups_deleted, referenced_rules_deleted=referenced_rules_deleted)

    def decommission_server(self, servers_to_decommission):

        if type(servers_to_decommission) is str:
            servers_to_decommission = [servers_to_decommission]

        found_obj = False
        del_response_objects = []

        # query all addresses and loop through to find all addresses
        addresses = self.get_addresses()

        for decomm_server in servers_to_decommission:
            for address in addresses:
                if 'ip-netmask' in address and f"{decomm_server}/32" == address['ip-netmask'] or 'ip-netmask' in address and f"{decomm_server}" == address['ip-netmask']:

                    self.logger.info(f"\nDeleting {address['@name']}...\n")

                    del_resp = self.delete_address(address['@name'], force=True)

                    self.logger.info(f"Deleted {address['@name']}")
                    del_response_objects.append(del_resp)

                    found_obj = True

        # if not found_obj:
        #     print("No addresses found!")

        return del_response_objects


