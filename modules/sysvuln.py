import ldap3
from ldap3 import *
from modules.clogging import Logging
import os
from modules.common import *

class SystemVulnCheck:
    dependencies = ["systems"]

    """
    This checks a list of ips for vulnerabilities. Namely: smb_signing, webdav, and printspooler. In the
    case where the ip appears in the domain controller list it also checks for ldap_signing, petitpotam, eternalblue, 
    dfscoerce, zerologon (work in progress), and nopac. This also can be very noisy.

    Num of LDAP queries: 1
    Created files: 0
    """
    def __init__(self, system_ips: list, dc_ips: list, username: str, password: str, hash: str, quiet: bool):
        self.system_ips = system_ips
        self.dc_ips = dc_ips
        self.username = username
        self.password = password
        self.hash = hash
        self.quiet = quiet
        self.dc_ips = dc_ips

    def run(self):
        Logging.header("Systems Vulnerability Checks")

        if(len(self.system_ips) > 0):
            Logging.info(f"Running checks for {len(self.system_ips)} systems")
        else:
            Logging.info("No systems to check")
            

        pHVal = "-p" 
        if(self.hash):
            pHVal = "-H"

        # remember pass = hash in the case where the hash is set

        for ip in self.system_ips:

            Logging.tool("CME", f"Running WebDav Scan for {ip}")
            if(self.quiet):
                ret = os.popen(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}'  -M webdav").read()
                if("Service enabled" in ret):
                    print(f"{bcolors.WARNING}WebDav/WebClient service enabled{bcolors.ENDC}")
            else:
                os.system(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M webdav")


            Logging.tool("CME", f"Running Spooler Service Scan for {ip}")
            if(self.quiet):
                ret = os.popen(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}'  -M spooler").read()
                if("Spooler service enabled" in ret):
                    print(f"{bcolors.WARNING}Spooler service enabled{bcolors.ENDC}")
            else:
                os.system(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}'  -M spooler")

            if(ip in self.dc_ips):
                print("")
                Logging.exclaim(f"{ip} is a domain controller, running extra checks")
                print("")

                Logging.tool("CME", f"Running Credentialed LDAP Signing Scan for {ip}")
                if(self.quiet):
                    ret = os.popen(f"crackmapexec ldap {ip} -u '{self.username}' {pHVal} '{self.password}' -M ldap-checker").read()
                    if("VULNERABLE" in ret):
                        print(f"{bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                else:
                    os.system(f"crackmapexec ldap {ip} -u '{self.username}' {pHVal} '{self.password}' -M ldap-checker")


                Logging.tool("CME", f"Running Petitpotam Scan for {ip}")
                if(self.quiet):
                    ret = os.popen(f"crackmapexec smb {ip} -u '' -p '' -M petitpotam").read()
                    if("VULNERABLE" in ret):
                        print(f"{bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                        uncredvuln = True
                else:
                    os.system(f"crackmapexec smb {ip} -u '' -p '' -M petitpotam")

                if(not uncredvuln):

                    Logging.tool("CME", f"Running Credentialed Petitpotam Scan for {ip}")
                    if(self.quiet):
                        ret = os.popen(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M petitpotam").read()
                        if("VULNERABLE" in ret):
                            print(f"{bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                    else:
                        os.system(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M petitpotam")


                Logging.tool("CME", f"Running Eternal Blue Scan for {ip}")
                if(self.quiet):
                    ret = os.popen(f"crackmapexec smb {ip} -u '' -p '' -M ms17-010").read()
                    if("VULNERABLE" in ret):
                        print(f"{bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                else:
                    os.system(f"crackmapexec smb {ip} -u '' -p '' -M ms17-010")



                Logging.tool("CME", f"Running DFSCoerce Scan for {ip}")
                if(self.quiet):
                    ret = os.popen(f"crackmapexec smb {ip} -u '' -p '' -M dfscoerce").read()
                    if("VULNERABLE" in ret):
                        print(f"{bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                else:
                    os.system(f"crackmapexec smb {ip} -u '' -p '' -M dfscoerce")

                
                """ TODO Zerologon is broken and does not close crackmapexec after completing """

                Logging.tool("CME", f"Running Credentialed NoPac Scan for {ip}")
                if(self.quiet):
                    ret = os.popen(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M nopac").read()
                    if("VULNERABLE" in ret):
                        print(f"{bcolors.FAIL}Vulnerable{bcolors.ENDC}")
                else:
                    os.system(f"crackmapexec smb {ip} -u '{self.username}' {pHVal} '{self.password}' -M nopac")

            Logging.end()
