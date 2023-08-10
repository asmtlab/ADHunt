import ldap3
from ldap3 import *
from modules.clogging import Logging
from modules.common import *
import os

class SMBEnumeration:
    dependencies = ["systems"]

    """
    Handles checking for smb misconfigurations and does enumeration by share spidering

    Num of LDAP queries: 0
    Created files: O(n)
    """
    def __init__(self, system_ips: list, username, password, hash, quiet, save_dir):
        self.system_ips = system_ips
        self.username = username
        self.password = password
        self.hash = hash
        self.quiet = quiet
        self.save_dir = save_dir


    def run(self):
        Logging.header("SMB Enumeration")

        pHVal = "-p"
        if(self.hash):
            pHVal = "-H"

        for ip in self.system_ips:
            Logging.info(f"Running Check for {ip}")

            Logging.tool("NMAP", f"Running SMB Signing Scan for {ip}")
            if(self.quiet):
                ret = os.popen(f"nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 {ip}").read()
                try:
                    print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} " + ret.split("|_")[1].split("\n")[0].strip())
                except:
                    print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} It appears SMB is not enabled on {ip}:445")
            else:
                os.system(f"nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 {ip}")

            # Share spidering
            Logging.tool("NMAP", f"Running CME Share Spidering for {ip}")
            if(self.quiet):
                ret = os.popen(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M spider_plus -o OUTPUT={self.save_dir}/smb").read()
            else:
                os.system(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M spider_plus -o OUTPUT={self.save_dir}/smb")
            
        print("")
        print(f"Files saved in {self.save_dir}/smb as [ip].txt")
