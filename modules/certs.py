import ldap3
from ldap3 import *
from modules.clogging import Logging
import os
from modules.common import *

class CertificateEnumeration:
    dependencies = ["ad-dns"]

    """
    This simply just uses certipy to find all vulnerable certicates within a domain.

    Num of LDAP queries: ?
    Created files: 3
    """
    def __init__(self, save_dir, username, password, hash, quiet, domain, dc_ip):
        self.save_dir = save_dir
        self.username = username
        self.password = password
        self.hash = hash
        self.quiet = quiet
        self.domain = domain
        self.domain_controller_ip = dc_ip

    def run(self):
        Logging.header("Certificate Services")

        Logging.tool("Certipy", "Scanning for Certificates")

        pHVal = '-p'
        if(self.hash):
            pHVal = '-hashes'
        
        if(self.quiet):
            ret = os.popen(f"certipy-ad find -u '{self.username}@{self.domain}' {pHVal} '{self.password}' -target-ip '{self.domain_controller_ip}' -dc-ip '{self.domain_controller_ip}' -vulnerable -output {self.save_dir}/").read()
            matched_lines = [line for line in ret.split('\n') if "failed" in line.lower()]
            for line in matched_lines:
                print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} {line[4:]}")

            Logging.fileinfo(f"{self.save_dir} as Certipy.*")
        else:
            os.system(f"certipy-ad find -u '{self.username}@{self.domain}' {pHVal} '{self.password}' -target-ip '{self.domain_controller_ip}' -dc-ip '{self.domain_controller_ip}' -vulnerable -output {self.save_dir}/")
