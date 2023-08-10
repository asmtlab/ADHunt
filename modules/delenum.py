import ldap3
from ldap3 import *
from modules.clogging import Logging
from impacket.ldap import ldaptypes


class DelegationEnumeration:
    def __init__(self, c: Connection, s: Server, save_dir: str):
        self.s = s
        self.c = c
        self.save_dir = save_dir

    def run(self):
        Logging.header("Delegation Enumeration")

        default_search_base = self.s.info.other.get('DefaultNamingContext')[0]

        ##### All objects with trusted for delegation -> output to file     					(userAccountControl:1.2.840.113556.1.4.803:=524288)
        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', search_scope=ldap3.SUBTREE, attributes=["samaccountname"], generator=False)

        with open(f"{self.save_dir}/full/objects_unconstrained_delegation_full.txt", "w") as f:
            f.write(str(self.c.response))
            
        count = 0
        with open(f"{self.save_dir}/delegation_unconstrained_objects.txt", "w") as f:
            for i in range(len(self.c.response)):
                if(self.c.response[i]["type"] == "searchResEntry"):
                    f.write(str(self.c.response[i]["attributes"]["samaccountname"]) + "\n")
                    count += 1

        Logging.info(f"Found: {count} AD Objects with Unconstrained Delegations")

        ##### All objects with trusted for auth delegation -> output to file     					(userAccountControl:1.2.840.113556.1.4.803:=16777216)
        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(msDS-AllowedToDelegateTo=*)', search_scope=ldap3.SUBTREE, attributes=["useraccountcontrol","samaccountname","msDS-AllowedToDelegateTo"], generator=False)

        with open(f"{self.save_dir}/full/objects_constrained_delegation_full.txt", "w") as f:
            f.write(str(self.c.response))
            
        countC = 0
        countCPT = 0
        with open(f"{self.save_dir}/delegation_constrained_objects.txt", "w") as f1:
            with open(f"{self.save_dir}/delegation_constrained_w_protocol_transition_objects.txt", "w") as f2:
                f1.write("SamAccountName: {objects that account can delegate for}\n")
                f1.write("====================================================================\n")

                f2.write("SamAccountName: {objects that account can delegate for}\n")
                f2.write("====================================================================\n")
                for i in range(len(self.c.response)):
                    if(self.c.response[i]["type"] == "searchResEntry"):
                        if(int(self.c.response[i]["attributes"]["useraccountcontrol"]) & 16777216):
                            f2.write(str(self.c.response[i]["attributes"]["samaccountname"]) + ": " + str(self.c.response[i]["attributes"]["msDS-AllowedToDelegateTo"]) + "\n")
                            countCPT += 1
                        else:
                            f2.write(str(self.c.response[i]["attributes"]["samaccountname"]) + ": " + str(self.c.response[i]["attributes"]["msDS-AllowedToDelegateTo"]) + "\n")
                            countC += 1

        Logging.info(f"Found: {countC} AD Objects with Constrained Delegations")
        Logging.info(f"Found: {countCPT} AD Objects with Constrained Delegations with Protocol Transition")


        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)', search_scope=ldap3.SUBTREE, attributes=["samaccountname","msDS-AllowedToActOnBehalfOfOtherIdentity"], generator=False)

        with open(f"{self.save_dir}/full/objects_rbcd_delegation_full.txt", "w") as f:
            f.write(str(self.c.response))
            
        count = 0
        with open(f"{self.save_dir}/delegation_rbcd_objects.txt", "w") as f:
            for i in range(len(self.c.response)):
                if(self.c.response[i]["type"] == "searchResEntry"):
                    name = str(self.c.response[i]["attributes"]["samaccountname"])

                    sF = '(|'
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(self.c.response[i]["attribute"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]))
                    for ace in sd['Dacl'].aces:
                        sF = sF + "(objectSid="+ace['Ace']['Sid'].formatCanonical()+")"
                    sF = sF + ')'

                    self.c.extend.standard.paged_search(search_base=default_search_base, search_filter=sF, search_scope=ldap3.BASE, attributes="*")

                    for dele in self.c.response:
                        f.write(f"{name} ::: delegates ::: {dele['attributes']['sAMAccountName']}\n")
                        count += 1

        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(ms-DS-MachineAccountQuota=*)', search_scope=ldap3.SUBTREE, attributes=["ms-DS-MachineAccountQuota"], generator=False)


        Logging.info(f"Found: {count} AD Objects with Resource Based Constrained Delegations")

        for resp in self.c.response:
            if(resp['type'] == "searchResEntry"):
                macctq = resp['attributes']['ms-DS-MachineAccountQuota']
                break

        if(macctq <= 0):
            Logging.ok("Machine Account Quota", macctq)
        else:
            Logging.fail("Machine Account Quota", macctq)


        Logging.fileinfo(f"delegation_*.txt in {self.save_dir}")

        Logging.end()
