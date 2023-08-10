import ldap3
from ldap3 import *
from modules.clogging import Logging

class PasswordPolicies:
    def __init__(self, c: Connection, s: Server):
        self.s = s
        self.c = c
    """
    Fetches password policies and prints them to the screen color coded by security.  Specifically it 
    fetches Minimum password length, Password History Length, Password Complexity Bit, Lockout Threshold, 
    Lockout Duration, and checks if LAPS is in use.

    Num of LDAP queries: 2
    Created files: 0
    """
    def run(self):
        Logging.header("Password Policies")
        
        default_search_base = self.s.info.other.get('DefaultNamingContext')[0]
        schema_search_base = self.s.info.other.get('SchemaNamingContext')[0]
        #### borrowed from: https://github.com/yaap7/ldapsearch-ad
        ### default password policies LDAP 									(objectClass=domainDNS)
        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(objectClass=domainDNS)', search_scope=ldap3.SUBTREE, attributes=['minPwdLength','pwdHistoryLength','pwdProperties','lockoutThreshold','lockoutDuration'], generator=False)

        for resp in self.c.response:
            if resp['type'] == 'searchResEntry':
                minPwd = resp['attributes']['minPwdLength']
                hisLen = resp['attributes']['pwdHistoryLength']
                compBit = resp['attributes']['pwdProperties'] & 1 > 0
                lthres = resp['attributes']['lockoutThreshold']
                ldur = resp['attributes']['lockoutDuration']

        if(minPwd < 15):
            Logging.fail("Password Minimum Length", minPwd)
        else:
            Logging.ok("Password Minimum Length", minPwd)

        if(hisLen <= 2):
            Logging.fail("Password History Length", hisLen)
        else:
            Logging.ok("Password History Length", hisLen)

        if(compBit == False):
            Logging.fail("Password Complexity Bit Set", "False")
        else:
            Logging.ok("Password Complexity Bit Set", "True")

        if(lthres == 0):
            Logging.fail("Lockout Threshold", "False")
        else:
            Logging.ok("Lockout Threshold", lthres)

        Logging.infov("Lockout Duration", ldur)

        ### fine grain password policies LDAP 									(objectClass=MsDS-PasswordSettings)

        ##### LAPS in use? Every user should be able to see the AdmPwdExpiration attribute			Check for 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=DOMAIN' DOMAIN schema should be in s.info
        laps_use = self.c.extend.standard.paged_search(search_base=schema_search_base, search_filter='(cn=ms-mcs-AdmPwdExpirationTime)', search_scope=ldap3.SUBTREE, attributes="name", generator=False)

        if(len(laps_use) > 0):
            Logging.ok("LAPS installed:", "True")
        else:
            Logging.fail("LAPS installed:", "False")
        
        Logging.end()

