import ldap3
from ldap3 import *
from modules.common import *
from modules.clogging import Logging
import dns.resolver

class NSEnumeration:
    dependencies = ["ad-dns"]
    
    def __init__(self, c: Connection, s: Server, NS_records: list, A_records: list, domain: str, scopeEnabled: bool, scopeExclude: list, scopeInclude: list):
        self.c = c
        self.s = s
        self.NS_records = NS_records
        self.A_records = A_records
        self.domain = domain
        self.scopeEnabled = scopeEnabled
        self.scopeInclude = scopeInclude
        self.scopeExclude = scopeExclude

    """
    This Enumerates through DNS Records and creates a dns_resolver which uses all the nameservers listed 
    in those records which have the ldap domain to try and resolve records.

    Num of LDAP queries: 0
    Created files: 0

    # TODO LIST
    # - aggressive mode: scope scanning?
    # - aggressive mode: which should perform reverse dns sweeping
    # - aggressive mode: perform a zone transfer
    # - aggressive mode: NSEC zone walking
    # - IPv6 support
    """
    def run(self):
        Logging.header("NameServer Enumeration")

        dns_resolver = dns.resolver.Resolver(configure=False)
        dns_resolver.nameservers = []

        # add all name servers that we have ips for to our dns resolver
        ns_processed = []
        for ns in self.NS_records:
            if(self.domain.lower() in ns["value"].lower()): # does the dns server sit within the domain we are scanning
                        
                if(ns['value'] in ns_processed):
                    continue

                ns_processed.append(ns['value'])

                if(not self.scopeEnabled): # if scope is enabled we will just check if the nameserver is in scope then use it if it is.
                    Logging.question(f"Found Nameserver {ns['value']}, use this (Y/n)")
                    use_name = input(": ")
                    if(not "Y" in use_name and not "y" in use_name):
                        continue

                # DNS records in AD are stored at the subdomain component so we need to fetch that
                query = ns["value"].split(self.domain.lower())[0] #is this a subdomain  [dc01].inlanefrieght.htb.
                if(query == "." or query == ""):
                    query = '@'
                else:
                    query = query[:-1]
                    

                matching_ips = set()
                for a in self.A_records:
                    if(a["name"].lower() == query):
                        matching_ips.add(a["value"])


                for ip in matching_ips:
                    if(self.scopeEnabled):
                        if(checkScope(ip, self.scopeExclude, self.scopeInclude)):
                            dns_resolver.nameservers.append(ip)
                    else:
                        Logging.question(f"Found IP: {ip} for {ns['value']}. Use this IP (Y/n)")
                        use = input(": ")
                        if("Y" in use or "y" in use):
                            dns_resolver.nameservers.append(ip)

        Logging.info(f"Name Servers have been set as {dns_resolver.nameservers}")

        return dns_resolver
