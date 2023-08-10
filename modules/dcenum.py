import ldap3
from ldap3 import *
from modules.clogging import Logging
from modules.common import *

class DCEnumeration:
    dependencies = ["ADDNSEnumeration"]
    """
    This queries the given LDAP server looking for obejcts running NTDSDSA service (should be dcs). These
    returned objects are compared against A records to try and extract an ip for the service. The list of 
    retrieved domain controller ips is returned.

    Num of LDAP queries: 1 + O(n)
    Created files: 0

    # TODO LIST
    # - aggressive mode: iterate through scope looking for common DC ports
    # - IPv6 support
    """

    def __init__(self, c: Connection, s: Server, A_records: list, scopeEnabled: bool, scopeExclude: list, scopeInclude: list, dc_ip: str):
        self.c = c
        self.s = s
        self.A_records = A_records
        self.scopeEnabled = scopeEnabled
        self.scopeExclude = scopeExclude
        self.scopeInclude = scopeInclude
        self.domain_controller_ip = dc_ip

    def run(self):
        pass

        Logging.header("Domain Controller Identification")

        # get all NTDSDSA objects, only domain controllers run this service
        self.c.extend.standard.paged_search(search_base=self.s.info.other.get('ConfigurationNamingContext')[0], search_filter='(objectClass=nTDSDSA)', search_scope=ldap3.SUBTREE, attributes=["distinguishedName"], generator=False)

        dc_ip = set()

        results = self.c.response 
        for i in range(len(results)):
            if(results[i]["type"] == "searchResEntry"):
                dName = results[i]["attributes"]["distinguishedName"]

                objectBase = dName[dName.index(",")+1:] # get the Parent CN=Child,CN=Parent,....DC=EXAMPLE,DC=NET

                self.c.extend.standard.paged_search(search_base=objectBase, search_filter='(objectClass=*)', search_scope=ldap3.BASE, attributes=["name"], generator=False)

                #should only return one response if we did it right
                domain_controller_name = self.c.response[0]['attributes']['name']

                Logging.info(f"Found {domain_controller_name}")

                # prevents duplicates in a messy way
                vals = list(set([x["value"] for x in self.A_records if x["name"].lower() == domain_controller_name.lower()]))

                if(len(vals) == 0):
                    Logging.exclaim(f"DNS search revealed no IPs for {domain_controller_name}, Skipping Vuln testing for this DC")
                    continue
                
                Logging.info(f"AD DNS search revealed the following Domain Controller: {domain_controller_name}")
                
                if(self.scopeEnabled):
                    for ip in vals:
                        if(checkScope(ip, self.scopeExclude, self.scopeInclude)):
                            dc_ip.add(ip)
                else:
                    print(f"Please select the IP which you would like to use for this DC:")

                    for ip_num in range(len(vals)):
                        print(f"[{ip_num}] {vals[ip_num]}")

                    print(f"[{ip_num+1}] Don't use any of these (skips dc specific testing)")

                    selected_ip = int(input(": "))
                    
                    if(selected_ip == ip_num+1):
                        print("Skipping DC Vuln testing for this system")
                        continue
                    elif(not selected_ip in range(len(vals))): #could make this re-ask for number
                        print("Unknown Input, Skipping Vuln testing for this DC") 
                        continue
                    else:
                        dc_ip.add(vals[selected_ip])
        
        dc_ip.add(self.domain_controller_ip)
        return dc_ip
