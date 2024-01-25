import requests
import warnings
import re

from decommission.modules.local_exceptions import *
import xml.etree.ElementTree as ET
from tqdm import tqdm
from colorama import Fore
import time


warnings.filterwarnings("ignore")


   


class PanRequests:

    def __init__(self):
        self.Username = ''
        self.Password = ''
        self.IP = "10.10.1.50"
        self.APIPort = 443
        self.pan_rest_version = ""
        self.headers = {"Content-Type": "application/json"}


    def _post_req(self, uri, payload=None):

        response = requests.post(f"https://{self.IP}:{self.APIPort}/{uri}", headers=self.headers,
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

        response = requests.put(f"https://{self.IP}:{self.APIPort}/{uri}", headers=self.headers
                                 ,json=payload,
                                 verify=False)
        
        return response

class _PanPaloShared(PanRequests):

    @staticmethod
    def _convert_reference_response_to_list(references_string):
        """
        This is used when trying to delete an object, but the response from API call is that the object is referenced in other places
        like rules or groups. 
        
        This will take the string of that gives where the references are located and converts it to a list

        This is needed because the references come back in one big string
        """
        # validate it is a reference
        if "cannot be deleted because of references from:" not in references_string:
            raise ValueError("Did not pass a string that is a Palo Alto reference as an argument")

        references = []
        for i in references_string.split('device-group ->'):
            
            if not "cannot be deleted because of references from:" in i:
                ref = {}
                r = re.match("((.*?)->)(.*)", i)
                ref['device-group'] = r.group(2).strip()
                #FIXME: run function to validate valid device-group here
                ref['reference'] = r.group(3).strip()
                references.append(ref)
        return references

    @staticmethod
    def watch(jobId, pb_description="Progress"):

        total = 100  # Total progress count (100%)
        with tqdm(total=total, desc=pb_description, bar_format=Fore.LIGHTBLUE_EX + "{l_bar}{bar:25}|") as pbar:
            while True:
                job_status = _PanPaloShared.check_status_of_job(jobId)
                progress = int(job_status['progress'])
                if progress > 100:
                    progress = 100
                pbar.update(progress - pbar.n)  # Update progress bar to the current progress
                if progress >= 100:
                    
                    break
                time.sleep(1) 

    def commit(self, watch=False, force=False):
        '''
        returns job ID 

        IF no job ID then returns None
        '''
        uri = f"?key={self.headers['X-PAN-Key']}&type=commit&cmd=<commit></commit>" if not force else f"?key={self.headers['X-PAN-Key']}&type=commit&cmd=<commit><force></force></commit>"

        
        print("\nCommitting changes..")
        resp = self._get_req(self.xml_uri+uri)
        responseXml = ET.fromstring(resp.content)

        try:
            jobId = responseXml.find('result').find('job').text

            if not watch:  # even if watching, this verifies if there is indeed a job id. There won't be one if there is nothing to commit
                return jobId
        except:
            return None
        
        if watch:
            _PanPaloShared.watch(jobId, pb_description="Commit Progress")


    
    def push_to_devices(self, watch=False):
        '''
        returns job ID 

        IF no job ID then returns None
        '''
        uri = f'''?key={self.headers['X-PAN-Key']}&type=commit&action=all&cmd=<commit-all><shared-policy><admin><member>{self.Username}</member></admin></shared-policy></commit-all>'''
        
        print("\nPushing changes..")
        resp = self._get_req(self.xml_uri+uri)
        responseXml = ET.fromstring(resp.content)
      
        try:
            jobId = responseXml.find('result').find('job').text

            if not watch:  # even if watching, this verifies if there is indeed a job id. There won't be one if there is nothing to commit
                return jobId
        except:
            return None

        if watch:
            _PanPaloShared.watch(jobId, pb_description="Push to Devices Progress")


    def login(self):
        uri = f'?type=keygen&user={self.Username}&password={self.Password}'
        try:
            resp = self._post_req(self.xml_uri+uri)
            resp.raise_for_status()
            self.LoggedIn = True
            responseXml = ET.fromstring(resp.content)
            key = responseXml.find('result').find('key')
            self.headers['X-PAN-Key'] = key.text
        except Exception:

            if 'invalid credential' in resp.content.decode('utf-8').lower():
                raise Exception("Invalid Credentials.")
            else:
                raise Exception(resp.content)
    
    def check_status_of_job(self, jobID):
        ''' 
        check status goes from ACT
        check result'''

        uri = f"?key={self.headers['X-PAN-Key']}&type=op&cmd=<show><jobs><id>{jobID}</id></jobs></show>"
        
        
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

    rest_uri = "/restapi/v10.1/"
    xml_uri = "/api/"


    def __init__(self, panorama_mgmt_ip):
        super().__init__()
        self.IP = panorama_mgmt_ip
        self.LoggedIn = False

    

    # def login(self):
    #     uri = f'?type=keygen&user={self.Username}&password={self.Password}'
    #     try:
    #         resp = self._post_req(self.xml_uri+uri)
    #         resp.raise_for_status()
    #         self.LoggedIn = True
    #         responseXml = ET.fromstring(resp.content)
    #         key = responseXml.find('result').find('key')
    #         self.headers['X-PAN-Key'] = key.text
    #     except Exception:

    #         if 'invalid credential' in resp.content.decode('utf-8').lower():
    #             raise Exception("Invalid Credentials.")
    #         else:
    #             raise Exception(resp.content)

    # def _watch(self, jobId, pb_description="Progress"):
        
    #         total = 100  # Total progress count (100%)
    #         with tqdm(total=total, desc=pb_description, bar_format=Fore.LIGHTBLUE_EX + "{l_bar}{bar:25}|") as pbar:
    #             while True:
    #                 job_status = self.check_status_of_job(jobId)
    #                 progress = int(job_status['progress'])
    #                 if progress > 100:
    #                     progress = 100
    #                 pbar.update(progress - pbar.n)  # Update progress bar to the current progress
    #                 if progress >= 100:
                        
    #                     break
    #                 time.sleep(1)

    # def commit(self, watch=False, force=False):
    #     '''
    #     returns job ID 

    #     IF no job ID then returns None
    #     '''
    #     uri = f"?key={self.headers['X-PAN-Key']}&type=commit&cmd=<commit></commit>" if not force else f"?key={self.headers['X-PAN-Key']}&type=commit&cmd=<commit><force></force></commit>"

        
    #     print("\nCommitting changes..")
    #     resp = self._get_req(self.xml_uri+uri)
    #     responseXml = ET.fromstring(resp.content)

    #     try:
    #         jobId = responseXml.find('result').find('job').text

    #         if not watch:  # even if watching, this verifies if there is indeed a job id. There won't be one if there is nothing to commit
    #             return jobId
    #     except:
    #         return None
        
    #     if watch:
    #         watch(jobId, pb_description="Commit Progress")
        
        
    # def push_to_devices(self, watch=False):
    #     '''
    #     returns job ID 

    #     IF no job ID then returns None
    #     '''
    #     uri = f'''?key={self.headers['X-PAN-Key']}&type=commit&action=all&cmd=<commit-all><shared-policy><admin><member>{self.Username}</member></admin></shared-policy></commit-all>'''
        
    #     print("\nPushing changes..")
    #     resp = self._get_req(self.xml_uri+uri)
    #     print(resp.content)
    #     responseXml = ET.fromstring(resp.content)
      
    #     try:
    #         jobId = responseXml.find('result').find('job').text

    #         if not watch:  # even if watching, this verifies if there is indeed a job id. There won't be one if there is nothing to commit
    #             return jobId
    #     except:
    #         return None


    #     if watch:
    #         self._watch(jobId, pb_description="Push to Devices Progress")


    # def check_status_of_job(self, jobID):
    #     ''' 
    #     check status goes from ACT
    #     check result'''

    #     uri = f"?key={self.headers['X-PAN-Key']}&type=op&cmd=<show><jobs><id>{jobID}</id></jobs></show>"
        
        
    #     resp = self._get_req(self.xml_uri+uri)
    #     responseXml = ET.fromstring(resp.content)

        

    #     try:
    #         return {"status": responseXml.find('result').find('job').find('status').text, 
    #                 "result": responseXml.find('result').find('job').find('result').text,
    #                 "progress": responseXml.find('result').find('job').find('progress').text
    #                 }
    #     except Exception as e:
    #         return {"error": e, "api_response": resp.content}    

    
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
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        return resp.json()
    

    def get_addresses(self, device_group):

        if device_group.lower() != "shared":
            uri = f'Objects/Addresses?location=device-group&device-group={device_group}'
        else:
            uri = f'Objects/Addresses?location={device_group}' 

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry']
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        return resp


    def get_addressgroup(self, address_group, device_group):

        if device_group.lower() != "shared":
            uri = f'Objects/AddressGroups?location=device-group&device-group={device_group}&name={address_group}'
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={address_group}'

        resp = self._get_req(self.rest_uri+uri)
        
        if resp.ok and "@total-count" in resp.json()['result'] and int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple address groups detected for address group '{address_group}' in Device Group '{device_group}'")
        
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        
        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]



    def delete_address_group(self, address_group, device_group, force=False, force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: This will do the same as force AND will remove references of references, etc.



        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced to same value. To have different values, set them both manually !!!!!
        '''

        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")
        
        if force_deletion_of_all_objects_referenced == None:
            force_deletion_of_all_objects_referenced = force

        if device_group.lower() != "shared":
            uri = f'Objects/AddressGroups?location=device-group&device-group={device_group}&name={address_group}'
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={address_group}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return resp.json()

        if "@status" in resp.json().keys() and resp.json()['@status'] == 'success':
            return resp.json()


          # If object can't be deleted because of references, this will delete refs if force switch == True

        self._filter_and_remove_obj_references(resp.json(), address_group, device_group, force=force) 
        

        # self._delete_refs_of_refs(resp.json())

        resp2 = self._del_req(self.rest_uri+uri)
        print(f"Deleted references. Now deleting address group {address_group} object.\n")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            print(f"Deleted address group object {address_group}")
            return resp2.json()
        else:
            try:
                raise Exception(f"Unable to delete object '{address_group}'. \n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_group}'.")
    

    def delete_address(self, address_name, device_group, force=False, force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: This will do the same as force AND will remove references of references, etc.



        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced to same value. To have different values, set them both manually !!!!!
        '''
        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")
        
        if force_deletion_of_all_objects_referenced == None:
            force_deletion_of_all_objects_referenced = force

        if device_group.lower() != "shared":
            uri = f'Objects/Addresses?location=device-group&device-group={device_group}&name={address_name}'
        else:
            uri = f'Objects/Addresses?location={device_group}&name={address_name}' 

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return resp.json()

        if "@status" in resp.json() and resp.json()['@status'] == 'success':
            return resp.json()
        

        # If object can't be deleted because of references, this will delete refs if force switch == True

        
        self._filter_and_remove_obj_references(resp.json(), address_name, device_group, force=force) 
        

        
        resp2 = self._del_req(self.rest_uri+uri)
        print(f"Deleted references. Now deleting address object {address_name}.")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            print(f"Deleted address object {address_name}")
            return resp2.json()
        else:
            try:
                raise Exception(f"Unable to delete object '{address_name}'. \n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_name}'.")


    # @staticmethod
    # def _convert_reference_response_to_list(references_string):
    #     """
    #     This is used when trying to delete an object, but the response from API call is that the object is referenced in other places
    #     like rules or groups. 
        
    #     This will take the string of that gives where the references are located and converts it to a list

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
    #             #FIXME: run function to validate valid device-group here
    #             ref['reference'] = r.group(3).strip()
    #             references.append(ref)
    #     return references

    def remove_address_from_rule(self, address_name, rule_name, rule_type, rulebase, device_group, direction, force=False, translation_direction=None, translation_type=None):
        '''
        '''

        if not type(rulebase) == str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")
        
        if device_group.lower() != "shared":
            uri = f'Policies/{rule_type}{rulebase}Rules?location=device-group&device-group={device_group}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'
        
        rule = self.get_rule(rule_name, rule_type, rulebase, device_group)


        # NAT RULE LOGIC
        if rule_type.lower() == 'nat': 
            if translation_type:
                if translation_type == 'static-ip':
                    # Unable to remove static ip as you cannot have none. Raising Exception
                    raise EmptySourceTranslationForRule(
                        description= "Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                        last_object= address_name, 
                        rule_name= rule_name,
                        rule_type= rule_type,
                        rulebase= rulebase, 
                        device_group= device_group, 
                        direction= direction,
                        translation_type = translation_type,
                        translation_direction = translation_direction
                                                        )
            else:
                rule[direction]['member'].remove(address_name)

                if len(rule[direction]['member']) == 0:
                    raise EmptyDirectionForRule(
                        description= "Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                        last_object= address_name, 
                        rule_name= rule_name, 
                        rule_type= rule_type,
                        rulebase= rulebase, 
                        device_group= device_group, 
                        direction= direction
                                                )
                payload = {'entry': [rule]}
            
                resp = self._put_req(self.rest_uri+uri, payload)

                return resp.json()
                
                
        elif rule_type.lower() == 'security':
        # Security Rule Logic           
            rule[direction]['member'].remove(address_name)

            if len(rule[direction]['member']) == 0:
                raise EmptyDirectionForRule(
                    description= "Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                    last_object= address_name, 
                    rule_name= rule_name, 
                    rule_type= rule_type,
                    rulebase= rulebase, 
                    device_group= device_group, 
                    direction= direction
                                            )

            payload = {'entry': [rule]}
            
            resp = self._put_req(self.rest_uri+uri, payload)

            return resp.json()
    
    def remove_addressgroup_from_rule(self, address_group, rule_name, rule_type, rulebase, device_group, direction, force=False):
        if not type(rulebase) == str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")
        
        if device_group.lower() != "shared":
            uri = f'Policies/{rule_type}{rulebase}Rules?location=device-group&device-group={device_group}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'

        rule = self.get_rule(rule_name, rule_type, rulebase, device_group)
        rule[direction]['member'].remove(address_group)

        if len(rule[direction]['member']) == 0:
            raise EmptyDirectionForRule(
                description= "Unable to remove address object from rule due to it is the last rule. Please, delete the rule.",
                last_object = address_group, 
                rule_name= rule_name, 
                rule_type= rule_type,
                rulebase= rulebase, 
                device_group= device_group, 
                direction= direction)
        
        payload = {'entry': [rule]}
        
        resp = self._put_req(self.rest_uri+uri, payload)

        return resp.json()

    def remove_address_from_addressgroup(self, address_name, address_group_name, device_group):

        if device_group.lower() != "shared":
            uri = f'Objects/AddressGroups?location=device-group&device-group={device_group}&name={address_group_name}'
        else:
            uri = f'Objects/AddressGroups?location={device_group}&name={address_group_name}'
        
        address_group = self.get_addressgroup(address_group_name, device_group)
       
        
        if len(address_group['static']['member']) == 1:

            #resp = self.delete_address_group(address_group_name, device_group)
            raise EmptyAddressGroup(
                description= f"Unable to remove address {address_name} due to it being the last object in the group. You must delete the group.",
                address_group= address_group_name,  
                device_group= device_group
                )
        
        address_group['static']['member'].remove(address_name)


        payload = {'entry': [address_group]}


        resp = self._put_req(self.rest_uri+uri, payload)

        if resp.status_code == 200:
            return resp.json()
        
        
        return resp.json()

    def delete_rule(self, rule_name, rule_type, rulebase, device_group):

        if device_group.lower() != "shared":
            uri = f'Policies/{rule_type}{rulebase}Rules?location=device-group&device-group={device_group}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'
        
        resp = self._del_req(self.rest_uri+uri)
    
        return resp.json()
    

    def get_rule(self, rule_name, rule_type, rulebase, device_group):

        # NOTE: For some reason rule comes back as an array, removed arrary on return
        
        if device_group.lower() != "shared":
            uri = f'Policies/{rule_type}{rulebase}Rules?location=device-group&device-group={device_group}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'
         
        
        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and "@total-count" in resp.json()['result'] and int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple rules detected for rule '{rule_name}' in Device Group '{device_group}'")
        
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        
        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]
        

        return resp.json()


    def remove_reference_from_object(self, reference, object_name, device_group, force=False):

        if "rulebase -> security -> rules ->" in reference:
            direction = "" #source or destination
            rulebase = "" # pre, post, or default
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
            
    
            resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type, 
                                             rulebase=rulebase, device_group=device_group, direction=direction)
            if '@status' in resp and resp['@status'] == "success":

                print(f"Removed address object_name from rule {rule_name} in DG {device_group}")
            
            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")


        elif "rulebase -> nat -> rules ->" in reference:
            direction = "" #source or destination
            rulebase = "" # pre, post, or default
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
                r = re.match(f"{rulebase}-rulebase -> nat -> rules -> (.*\.$)", reference)
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
                                            rulebase=rulebase, device_group=device_group, direction=direction, translation_type=translation_type, translation_direction=translation_direction)
            else:
                resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type, 
                                            rulebase=rulebase, device_group=device_group, direction=direction)
            
            if '@status' in resp and resp['@status'] == "success":

                print(f"Removed address object_name from rule {rule_name} in DG {device_group}")
            
            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")

        elif 'address-group -> ' in reference:
            r = re.match('^address-group -> (.*?) -> static', reference)
            address_group = r.group(1)

            resp = self.remove_address_from_addressgroup(object_name, address_group, device_group)
            if '@status' in resp and resp['@status'] == "success":

                print(f"Removed address {object_name} from address group {address_group}")

            



        else:
            print('RESPONSE:\n', resp)
            raise Exception(f"Unable to delete object {object_name} \nReferenced object type not supported for deletion:  {reference}'")


        
    def _filter_and_remove_obj_references(self, json_resp_from_failure_to_remove_delete_item, obj_name, device_group, force=False):
         # If object can't be deleted because of references, this will delete refs
        first_ref_has_not_been_deleted = True
        while first_ref_has_not_been_deleted:

            resp = json_resp_from_failure_to_remove_delete_item
            if resp['message'].lower() == "reference not zero" and "details" in resp:
                print(f"Found References for object {obj_name}. Remove object from References...")
                
                for detail in resp['details']:
                    if "@type" in detail and detail['@type'].lower() == "causeinfo":
                        for cause in detail['causes']:
                            if f"{obj_name} cannot be deleted because of references from:" in cause["description"]:
                                references = self._convert_reference_response_to_list(cause["description"])
                print("References: ")
                for reference in references:
                    print(f"- {reference}")
                print('\n\n')
                for reference in references:
                    try:
                        self.remove_reference_from_object(reference['reference'], object_name=obj_name, device_group=reference["device-group"])

                    except EmptyDirectionForRule as e:

                        if force:
                            self.delete_rule(rule_name=e.rule_name, rule_type=e.rule_type, rulebase=e.rulebase, device_group=e.device_group)
                            print(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e

                    except EmptyAddressGroup as e:
                        if force:
                            self.delete_address_group(address_group=e.address_group, device_group=e.device_group, force=force)
                        else:
                            raise e
                    
                    except EmptySourceTranslationForRule as e:

                        if force:
                            self.delete_rule(rule_name=e.rule_name, rule_type=e.rule_type, rulebase=e.rulebase, device_group=e.device_group)
                            print(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e
                                            
            first_ref_has_not_been_deleted = False
            
    
    def decommission_server(self, servers_to_decommission):
        address_objects_to_delete = []
        found_obj = False
        if type(servers_to_decommission) is str:
            servers_to_decommission = [servers_to_decommission]

        device_groups = self.get_devicegroups(include_shared=True)
        

        if type(device_groups) == dict and 'message' in device_groups.keys() and 'invalid cred' in device_groups['message'].lower():
            raise Exception("Invalid credentials for Panorama")
        
        for decomm_server in servers_to_decommission:
            for dg in device_groups:
                    
                # query all addresses and loop through to find all addresses
                addresses = self.get_addresses(dg['@name'])
                for address in addresses:
                    if 'ip-netmask' in address and f"{decomm_server}/32" == address['ip-netmask'] or 'ip-netmask' in address and f"{decomm_server}" == address['ip-netmask']:
                        # The following logic is to detect duplicate findings from an address being in a device group but shared into another, only need to delete 1 time
                        if '@loc' in address and address['@loc'] != address['@device-group']:
                            continue
                        elif '@loc' in address and address['@loc'] == address['@device-group'] or '@loc' not in address and '@device-group' in address or '@location' in address and address['@location'] == "shared":
                            print(f"\nDeleting {address['@name']} from {dg['@name']}...\n\n")
                            self.delete_address(address['@name'], dg['@name'], force=True) 
                            found_obj = True             
                        else:
                            raise Exception(f"Unable to remove address {address['@name']} in Device Group {dg['@name']}. \nRef")
                        

            if not found_obj:
                print("No addresses found!") #FIXME: should probably raise to make pipeline fail? Will decide later

    
    


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


    def get_sec_rules(self, location="vsys"):

        if location == "vsys":
            uri = f'Policies/SecurityRules?location={location}&{location}={self.vsys}'
        else:
            uri = f'Policies/SecurityRules?location={location}'

        resp = self._get_req(self.rest_uri+uri)
        
        return resp.json()
    
    
    def get_addresses(self, location):

        if location == "vsys":
            uri = f'Objects/Addresses?location={location}&{location}={self.vsys}'
        else:
            uri = f'Objects/Addresses?location={location}'

        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry']
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        return resp


    def get_addressgroup(self, address_group, location): 

        if location == "vsys":
            uri = f'Objects/AddressGroups?location={location}&{location}={self.vsys}'
        else:
            uri = f'Objects/AddressGroups?location={location}'


        resp = self._get_req(self.rest_uri+uri)
        
        if resp.ok and "@total-count" in resp.json()['result'] and int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple address groups detected for address group '{address_group}' in Device Group '{device_group}'")
        
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        
        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]



    def delete_address_group(self, address_group, location, force=False, force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: This will do the same as force AND will remove references of references, etc.



        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced to same value. To have different values, set them both manually !!!!!
        '''

        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")
        
        if force_deletion_of_all_objects_referenced == None:
            force_deletion_of_all_objects_referenced = force

        if location == "vsys":
            uri = f'Objects/AddressGroups?location={location}&{location}={self.vsys}'
        else:
            uri = f'Objects/AddressGroups?location={location}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return resp.json()

        if "@status" in resp.json().keys() and resp.json()['@status'] == 'success':
            return resp.json()


          # If object can't be deleted because of references, this will delete refs if force switch == True

        self._filter_and_remove_obj_references(resp.json(), address_group, device_group, force=force) 
        

        # self._delete_refs_of_refs(resp.json())

        resp2 = self._del_req(self.rest_uri+uri)
        print(f"Deleted references. Now deleting address group {address_group} object.\n")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            print(f"Deleted address group object {address_group}")
            return resp2.json()
        else:
            try:
                raise Exception(f"Unable to delete object '{address_group}'. \n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_group}'.")
    

    def delete_address(self, address_name, location, force=False, force_deletion_of_all_objects_referenced=None):
        '''
        params;
        force: This will remove direct references (delete the reference if it is last object in references)
        force_deletion_of_all_objects_referenced: This will do the same as force AND will remove references of references, etc.



        !!!!! WARNING: setting force will ALSO set force_deletion_of_all_objects_referenced to same value. To have different values, set them both manually !!!!!
        '''
        if not isinstance(force, bool):
            raise ValueError("force must be a boolean")
        
        if force_deletion_of_all_objects_referenced == None:
            force_deletion_of_all_objects_referenced = force


        if location == "vsys":
            uri = f'Objects/Addresses?location={location}&{location}={self.vsys}'
        else:
            uri = f'Objects/Addresses?location={location}'

        resp = self._del_req(self.rest_uri+uri)

        if not force:
            return resp.json()

        if "@status" in resp.json() and resp.json()['@status'] == 'success':
            return resp.json()
        

        # If object can't be deleted because of references, this will delete refs if force switch == True

        
        self._filter_and_remove_obj_references(resp.json(), address_name, device_group, force=force) 
        

        
        resp2 = self._del_req(self.rest_uri+uri)
        print(f"Deleted references. Now deleting address object {address_name}.")

        if "@status" in resp2.json() and resp2.json()['@status'] == 'success':
            print(f"Deleted address object {address_name}")
            return resp2.json()
        else:
            try:
                raise Exception(f"Unable to delete object '{address_name}'. \n Error: {resp2.json()}")
            except:
                raise Exception(f"Unable to delete object '{address_name}'.")

    def remove_address_from_rule(self, address_name, rule_name, rule_type, rulebase, location, direction, force=False, translation_direction=None, translation_type=None):
        '''
        '''

        if not type(rulebase) == str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")
        


        if location == "vsys":
            uri = f'Policies/{rule_type}{rulebase}Rules?location={location}&{location}={self.vsys}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={location}'

        rule = self.get_rule(rule_name, rule_type, rulebase, location)


        # NAT RULE LOGIC
        if rule_type.lower() == 'nat': 
            if translation_type:
                if translation_type == 'static-ip':
                    # Unable to remove static ip as you cannot have none. Raising Exception
                    raise EmptySourceTranslationForRule(
                        description= "Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                        last_object= address_name, 
                        rule_name= rule_name,
                        rule_type= rule_type,
                        rulebase= rulebase, 
                        device_group= location, 
                        direction= direction,
                        translation_type = translation_type,
                        translation_direction = translation_direction
                                                        )
            else:
                rule[direction]['member'].remove(address_name)

                if len(rule[direction]['member']) == 0:
                    raise EmptyDirectionForRule(
                        description= "Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                        last_object= address_name, 
                        rule_name= rule_name, 
                        rule_type= rule_type,
                        rulebase= rulebase, 
                        device_group= device_group, 
                        direction= direction
                                                )
                payload = {'entry': [rule]}
            
                resp = self._put_req(self.rest_uri+uri, payload)

                return resp.json()
                
                
        elif rule_type.lower() == 'security':
        # Security Rule Logic           
        
            rule[direction]['member'].remove(address_name)

            if len(rule[direction]['member']) == 0:
                raise EmptyDirectionForRule(
                    description= "Unable to remove address object from rule due to it is the last object in rule. Please, delete the rule.",
                    last_object= address_name, 
                    rule_name= rule_name, 
                    rule_type= rule_type,
                    rulebase= rulebase, 
                    device_group= location, 
                    direction= direction
                                            )

            payload = {'entry': [rule]}
            
            resp = self._put_req(self.rest_uri+uri, payload)

            return resp.json()
    
    def remove_addressgroup_from_rule(self, address_group, rule_name, rule_type, rulebase, location, direction, force=False):
        if not type(rulebase) == str:
            raise ValueError("rulebase arg must be string.")
        if rulebase.lower() not in ['pre', 'post', 'default']:
            raise ValueError("rulebase arg must be 'pre' or 'post'")
        

        if location == "vsys":
            uri = f'Policies/{rule_type}{rulebase}Rules?location={location}&{location}={self.vsys}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={location}'

            
        rule = self.get_rule(rule_name, rule_type, rulebase, location)
        rule[direction]['member'].remove(address_group)

        if len(rule[direction]['member']) == 0:
            raise EmptyDirectionForRule(
                description= "Unable to remove address object from rule due to it is the last rule. Please, delete the rule.",
                last_object = address_group, 
                rule_name= rule_name, 
                rule_type= rule_type,
                rulebase= rulebase, 
                device_group= location, 
                direction= direction)
        
        payload = {'entry': [rule]}
        
        resp = self._put_req(self.rest_uri+uri, payload)

        return resp.json()

    def remove_address_from_addressgroup(self, address_name, address_group_name, location):

        if location == "vsys":
            uri = f'Objects/AddressGroups?location={location}&{location}={self.vsys}'
        else:
            uri = f'Objects/AddressGroups?location={location}'
        
        address_group = self.get_addressgroup(address_group_name, location)
       
        
        if len(address_group['static']['member']) == 1:

            #resp = self.delete_address_group(address_group_name, device_group)
            raise EmptyAddressGroup(
                description= f"Unable to remove address {address_name} due to it being the last object in the group. You must delete the group.",
                address_group= address_group_name,  
                device_group= location
                )
        
        address_group['static']['member'].remove(address_name)


        payload = {'entry': [address_group]}


        resp = self._put_req(self.rest_uri+uri, payload)

        if resp.status_code == 200:
            return resp.json()
        
        
        return resp.json()

    def delete_rule(self, rule_name, rule_type, rulebase, device_group):

        if device_group.lower() != "shared":
            uri = f'Policies/{rule_type}{rulebase}Rules?location=device-group&device-group={device_group}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'
        
        resp = self._del_req(self.rest_uri+uri)
    
        return resp.json()
    

    def get_rule(self, rule_name, rule_type, rulebase, device_group):

        # NOTE: For some reason rule comes back as an array, removed arrary on return
        
        if device_group.lower() != "shared":
            uri = f'Policies/{rule_type}{rulebase}Rules?location=device-group&device-group={device_group}&name={rule_name}'
        else:
            uri = f'Policies/{rule_type}{rulebase}Rules?location={device_group}&name={rule_name}'

        
        
        resp = self._get_req(self.rest_uri+uri)

        if resp.ok and "@total-count" in resp.json()['result'] and int(resp.json()['result']['@total-count']) > 1:
            raise Exception(f"Multiple rules detected for rule '{rule_name}' in Device Group '{device_group}'")
        
        elif resp.ok and "@total-count" in resp.json()['result'] and resp.json()['result']['@total-count'] == "0":
            return [] # empty
        
        elif resp.ok and 'entry' in resp.json()['result']:
            return resp.json()['result']['entry'][0]
        

        return resp.json()
    
     
    def remove_reference_from_object(self, reference, object_name, device_group, force=False):

        if "rulebase -> security -> rules ->" in reference:
            direction = "" #source or destination
            rulebase = "" # pre, post, or default
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
            
    
            resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type, 
                                             rulebase=rulebase, device_group=device_group, direction=direction)
            if '@status' in resp and resp['@status'] == "success":

                print(f"Removed address object_name from rule {rule_name} in DG {device_group}")
            
            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")


        elif "rulebase -> nat -> rules ->" in reference:
            direction = "" #source or destination
            rulebase = "" # pre, post, or default
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
                r = re.match(f"{rulebase}-rulebase -> nat -> rules -> (.*\.$)", reference)
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
                                            rulebase=rulebase, device_group=device_group, direction=direction, translation_type=translation_type, translation_direction=translation_direction)
            else:
                resp = self.remove_address_from_rule(address_name=object_name, rule_name=rule_name, rule_type=rule_type, 
                                            rulebase=rulebase, device_group=device_group, direction=direction)
            
            if '@status' in resp and resp['@status'] == "success":

                print(f"Removed address object_name from rule {rule_name} in DG {device_group}")
            
            else:
                raise Exception(f"Unable to delete object {object_name} \nRespone Obj: {resp}'")

        elif 'address-group -> ' in reference:
            r = re.match('^address-group -> (.*?) -> static', reference)
            address_group = r.group(1)

            resp = self.remove_address_from_addressgroup(object_name, address_group, device_group)
            if '@status' in resp and resp['@status'] == "success":

                print(f"Removed address {object_name} from address group {address_group}")

            



        else:
            print('RESPONSE:\n', resp)
            raise Exception(f"Unable to delete object {object_name} \nReferenced object type not supported for deletion:  {reference}'")


        
    def _filter_and_remove_obj_references(self, json_resp_from_failure_to_remove_delete_item, obj_name, device_group, force=False):
         # If object can't be deleted because of references, this will delete refs
        first_ref_has_not_been_deleted = True
        while first_ref_has_not_been_deleted:

            resp = json_resp_from_failure_to_remove_delete_item
            if resp['message'].lower() == "reference not zero" and "details" in resp:
                print(f"Found References for object {obj_name}. Remove object from References...")
                
                for detail in resp['details']:
                    if "@type" in detail and detail['@type'].lower() == "causeinfo":
                        for cause in detail['causes']:
                            if f"{obj_name} cannot be deleted because of references from:" in cause["description"]:
                                references = self._convert_reference_response_to_list(cause["description"])
                print("References: ")
                for reference in references:
                    print(f"- {reference}")
                print('\n\n')
                for reference in references:
                    try:
                        self.remove_reference_from_object(reference['reference'], object_name=obj_name, device_group=device_group)

                    except EmptyDirectionForRule as e:

                        if force:
                            self.delete_rule(rule_name=e.rule_name, rule_type=e.rule_type, rulebase=e.rulebase, device_group=e.device_group)
                            print(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e

                    except EmptyAddressGroup as e:
                        if force:
                            self.delete_address_group(address_group=e.address_group, device_group=e.device_group, force=force)
                        else:
                            raise e
                    
                    except EmptySourceTranslationForRule as e:

                        if force:
                            self.delete_rule(rule_name=e.rule_name, rule_type=e.rule_type, rulebase=e.rulebase, device_group=e.device_group)
                            print(f"Deleted reference: Rule {e.rule_name}")
                        else:
                            raise e
                                            
            first_ref_has_not_been_deleted = False
            
    
    def decommission_server(self, servers_to_decommission):
        address_objects_to_delete = []
        found_obj = False
        if type(servers_to_decommission) is str:
            servers_to_decommission = [servers_to_decommission]

        device_groups = self.get_devicegroups(include_shared=True)
        

        if type(device_groups) == dict and 'message' in device_groups.keys() and 'invalid cred' in device_groups['message'].lower():
            raise Exception("Invalid credentials for Panorama")
        
        for decomm_server in servers_to_decommission:
            for dg in device_groups:
                    
                # query all addresses and loop through to find all addresses
                addresses = self.get_addresses(dg['@name'])
                for address in addresses:
                    if 'ip-netmask' in address and f"{decomm_server}/32" == address['ip-netmask'] or 'ip-netmask' in address and f"{decomm_server}" == address['ip-netmask']:
                        
                        # The following logic is to detect duplicate findings from an address being in a device group but shared into another, only need to delete 1 time
                        if '@loc' in address and address['@loc'] != address['@device-group']:
                            continue
                        elif '@loc' in address and address['@loc'] == address['@device-group'] or '@loc' not in address and '@device-group' in address or '@location' in address and address['@location'] == "shared"  :
                            print(f"\nDeleting {address['@name']} from {dg['@name']}...\n\n")
                            
                            del_resp = self.delete_address(address['@name'], dg['@name'], force=True) 
                        

                            #pano.delete_address(address['@name'], dg['@name'], force=True)
                            # print(f"Deleted address {address['@name']}")
                            found_obj = True           
                        else:
                            raise Exception(f"Unable to remove address {address['@name']} in Device Group {dg['@name']}. \nRef")
                        

            if not found_obj:
                print("No addresses found!") #FIXME: should probably raise to make pipeline fail? Will decide later

    
    




if __name__ == "__main__":
    
    from getpass import getpass
    pano = PanoramaAPI("10.10.1.52")
    #pano = PanOSAPI("10.10.200.220")
    pano.Username = input("Username: ")
    pano.Password = getpass()
    decomm_server = "123.123.123.121"

    print("logging in")
    pano.login()
    print('logged in')
    
    #pano.decommission_server(decomm_server)






    
    




    
