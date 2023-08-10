import ldap3
from ldap3 import *
from modules.common import *
from modules.clogging import Logging

class SystemEnumeration:
    """
    This searches for IPs with multiple methods. It first searches through a list of A records to find ips 
    then it queries the ldap server looking for services.  Once it finds those services it trys to resolve 
    them with the dns_resolver and appends those ips to its scan list. This can be noisy.

    Num of LDAP queries: 1
    Created files: 0
    
    # TODO LIST 
    # - IPv6 support
    # - save ips somewhere?
    # - aggressive: full scope scanning
    """

    def __init__(self, c: Connection, s: Server, dns_resolver, A_records: list, scopeEnabled: bool, scopeExclude: list, scopeInclude: list, dc_ip: str):
        self.c = c
        self.s = s
        self.dns_resolver = dns_resolver
        self.A_records = A_records
        self.scopeEnabled = scopeEnabled
        self.scopeExclude = scopeExclude
        self.scopeInclude = scopeInclude
        self.domain_controller_ip = dc_ip

    def run(self):
        Logging.header("System Enumeration")

        Logging.info(f"Finding IPs to scan")

        system_ips = set()
        seen_ips = set()

        default_search_base = self.s.info.other.get('DefaultNamingContext')[0]

        # LinWinPwn uses the adinaddump service to find ips, we will use 2 methods

        # Method 1: search our previously obtained A records for IPS
        for a in self.A_records:
            if(a['value'] in seen_ips):
                continue
            seen_ips.add(a['value'])
            if(self.scopeEnabled):
                if(checkScope(a['value'], self.scopeExclude, self.scopeInclude)):
                    system_ips.add(a['value'])
            else:
                Logging.question(f"AD-DNS found ip: {a['value']}, scan this IP (Y/n)?")
                ip_dns = input(": ")
                if("y" in ip_dns.lower()):
                    system_ips.add(a['value'])

        # Method 2: Check for services running and ask the DNS servers we found to get us an ip for the services
        # resolver should already be setup
        print("Checking for services")

        self.c.extend.standard.paged_search(search_base=default_search_base, search_filter='(dnshostname=*)', search_scope=ldap3.SUBTREE, attributes=["dnshostname"], generator=False)

        for section in self.c.response:
            if(section["type"] == "searchResEntry"):
                print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found service: {section['attributes']['dnshostname']}")

                # try and resolve these to ips with our resolver
                try:
                    ans = self.dns_resolver.resolve(section['attributes']['dnshostname'], 'A')
                except:
                    print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Could not resolve {section['attributes']['dnshostname']}.")
                    continue

                for response in ans:
                    if(response.to_text() in seen_ips):
                        continue
                    seen_ips.add(response.to_text())
                    
                    if(self.scopeEnabled):
                        if(checkScope(response.to_text(), self.scopeExclude, self.scopeInclude)):
                            system_ips.add(response.to_text())
                    else:
                        Logging.question(f"DNS Resolved an IP {response.to_text()}, use this IP (y/n)")
                        ip_dns = input(": ")
                        if("y" in ip_dns.lower()):
                            system_ips.add(response.to_text())
        
        system_ips.add(self.domain_controller_ip)
        return system_ips
    