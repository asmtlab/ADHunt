#!/usr/bin/python3

import sys
import os
import argparse
import ipaddress
import textwrap

from modules.common import *
from modules.addns import ADDNSEnumeration
from modules.passpol import PasswordPolicies
from modules.nsenum import NSEnumeration
from modules.dcenum import DCEnumeration
from modules.sysenum import SystemEnumeration
from modules.certs import CertificateEnumeration
from modules.delenum import DelegationEnumeration
from modules.smbenum import SMBEnumeration
from modules.sysvuln import SystemVulnCheck
from modules.usrenum import UserEnumeration

class RawFormatter(argparse.HelpFormatter):
    def _fill_text(self, text, width, indent):
        return "\n".join([textwrap.fill(line, width) for line in textwrap.indent(textwrap.dedent(text), indent).splitlines()])

class AD_Hunt:
	modules = {
		"pass-pols": PasswordPolicies,
		"delegations": DelegationEnumeration,
		"users": UserEnumeration,
		"certificates": CertificateEnumeration,
		"ad-dns": ADDNSEnumeration,
		"nameservers": NSEnumeration,
		"domain-controllers": DCEnumeration,
		"systems": SystemEnumeration,
		"system-vulns": SystemVulnCheck,
		"smb": SMBEnumeration,
	}

	"""
	This runs system commands to install the dependancies needed for this program
	"""
	def install(self):
		print("Installing... (are you root?)")
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Installing pip3{bcolors.ENDC}")
		os.system("apt install python3-pip")
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Installing Impacket{bcolors.ENDC}")
		os.system("pip3 install impacket")
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Installing CME{bcolors.ENDC}")
		os.system("apt install crackmapexec")
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Installing Certipy{bcolors.ENDC}")
		os.system("apt install certipy-ad")
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Installing NMAP{bcolors.ENDC}")
		os.system("apt install nmap")
		sys.exit(0)
	
	"""
	runs the check functions
	"""
	def run(self):
		args = self.args
		# Run scans

		if(not args.just or "pass-pols" in args.just):
			passpol = PasswordPolicies(self.c, self.s)
			passpol.run()
		if(not args.just or "delegations" in args.just):
			delenum = DelegationEnumeration(self.c, self.s, self.args.save_dir)
			delenum.run()
		if(not args.just or "users" in args.just):
			usrenum = UserEnumeration(self.c, self.s, self.args.save_dir, self.args.username, self.args.password, self.args.hash, self.args.domain_controller_ip)
			usrenum.run()
		if(not args.just or "certificates" in args.just):
			certs = CertificateEnumeration(self.args.save_dir, self.args.username, self.args.password, self.args.hash, self.args.quiet, self.args.domain, self.args.domain_controller_ip)
			certs.run()
		if(not args.just or any(x in ['ad-dns', 'nameservers', 'domain-controllers', 'systems', 'system-vulns', 'smb'] for x in args.just)):
			addns = ADDNSEnumeration(self.c, self.s, self.args.save_dir, self.args.fresh) 
			ns_r, a_r = addns.run()
		if(not args.just or any(x in ['nameservers', 'domain-controllers', 'systems', 'system-vulns', 'smb'] for x in args.just)):
			nseenum = NSEnumeration(self.c, self.s, ns_r, a_r, self.args.domain, self.args.scopeEnabled, self.args.scopeExclude, self.args.scopeInclude)
			dns_resolver = nseenum.run()
		if(not args.just or any(x in ['domain-controllers', 'systems', 'system-vulns', 'smb'] for x in args.just)):
			dcenum = DCEnumeration(self.c, self.s, a_r, self.args.scopeEnabled, self.args.scopeExclude, self.args.scopeInclude, self.args.domain_controller_ip)
			dc_ips = dcenum.run()
		if(not args.just or any(x in ['systems', 'system-vulns', 'smb'] for x in args.just)):
			sysenum = SystemEnumeration(self.c, self.s, dns_resolver, a_r, self.args.scopeEnabled, self.args.scopeExclude, self.args.scopeInclude, self.args.domain_controller_ip)
			system_ips = sysenum.run()

		if(not args.no_scan):
			if(not args.just or 'system-vulns' in args.just):
				sysvuln = SystemVulnCheck(system_ips, dc_ips, self.args.username, self.args.password, self.args.hash, self.args.quiet) #depends on systems, domain_controllers
				sysvuln.run()
			if(not args.just or 'smb' in args.just):
				smbenum = SMBEnumeration(system_ips, self.args.username, self.args.password, self.args.hash, self.args.quiet, self.args.save_dir)
				smbenum.run()
	
	"""
	Gets commandline arguments from the user and parses them. Then it calls the setup method.
	"""
	def __init__(self):
		program_descripton = f"""
		Active Directory Enumeration Tool
		
		Example usage:

		$ python3 adhunt.py --install
		$ python3 adhunt.py --dc-ip 10.129.150.235 -u grace -p Inlanefreight01! --scope i:10.129.0.0/16,e:10.129.10.10 --no-scan --quiet
		$ python3 adhunt.py --dc-ip 10.129.23.200 -u user -H "5B0391923089960876FDE78389BE2CE2:F1223169E60A2513B6D8C93AE3A77B49" --scope i:10.129.0.100
		
		"""


		parser = argparse.ArgumentParser(prog="python3 adhunt.py", description=program_descripton, formatter_class=RawFormatter)

		parser.add_argument("-i", "--install", action='store_true', help="install nessecary components")
		
		parser.add_argument("--dc-ip", dest="domain_controller_ip", help="The IP of the domain controller targeted for enumeration")
		
		parser.add_argument("-u", "--username", help="The username of the user for enumation purposes")
		
		parser.add_argument("-p", "--password", help="The password of the supplied user")
		
		parser.add_argument("-H", "--hash", help="The hash for pass the hash authentication format [LM:]NTLM")
		
		parser.add_argument("-d", "--domain", help="The domain of the given user, if not provided fetched automatically from LDAP service name")
		
		parser.add_argument("-s", "--scope", help=f"The scope of valid ips for checking ranges when performing vulnerability scanning and enumeration. Include ranges with i, and exclude with e. Seperate args by commas, For example a valid scope would be {bcolors.HELPEXAMPLE}--scope i:10.129.0.0/24,e:10.129.0.129{bcolors.ENDC}")
		
		parser.add_argument("--detection-mode", choices={"aggressive", "moderate", "passive", "stealthy"}, 
		      help=f"passive [default] (only scan ips found from ad dns information), moderate (scan ips from ad dns and perform regular dns enumeration), aggressive (scan everything in scope), stealthy (TODO)") #TODO
		
		parser.add_argument("-q", "--quiet", help="Don't display output from tools", action="store_true")

		parser.add_argument("--no-scan", dest="no_scan", help="Do not scan found ips for vulnerabilities", action="store_true")
		
		parser.add_argument("--no-banner", dest="no_banner", help="Do not display the banner", action='store_true')
		
		parser.add_argument("--ssl", help="Should connections be made with ssl", action='store_true')

		parser.add_argument("--fresh", help="Should modules load from the save dir or regenerate all data", action='store_true')

		self.tests = self.modules.keys()
		parser.add_argument("--just", choices=self.tests, help="only run the specified check(s) and its required other checks", nargs="+")

		self.args = parser.parse_args()

		if(os.name != "posix"):
			print("AD Hunt only works in a linux enviroment.")
			sys.exit(1)

		if(sys.version_info[0] != 3):
			print("{0}Warning: This script has only been tested for python3{1}".format(bcolors.WARNING, bcolors.ENDC))
			sys.exit(1)

		self.setup()
	
	"""
	"Private" function that sets up the configuration. It checks to make sure this is the correct
	python version and that all arguments have been passed appropriately. It handles managing installation
	and prints the banner for the program

	# TODO LIST
	# - ensure all required dependancies are installed before continuing
	"""
	def setup(self):
				### Header
		args = self.args

		if(args.no_banner):
			print("ADHunt by Charlie Fligg")
			print("")
		else:
			print(rf'''{bcolors.OKCYAN} ______  _____       __  __  __  __  __   __  ______  
/\  __ \/\  __-.    /\ \_\ \/\ \/\ \/\ "-.\ \/\__  _\ 
\ \  __ \ \ \/\ \   \ \  __ \ \ \_\ \ \ \-.  \/_/\ \/ 
 \ \_\ \_\ \____-    \ \_\ \_\ \_____\ \_\\"\_\ \ \_\ 
  \/_/\/_/\/____/     \/_/\/_/\/_____/\/_/ \/_/  \/_/ {bcolors.ENDC}''')

															
		print("") 
		print("")              

		if(args.install):
			self.install()

		# this has to be installed so it needs to only be imported after we have had a chance to install everything
		import ldap3


		if(not args.domain_controller_ip):
			print("Must specify the ip of a domain controller with -dc-ip") # TODO eventually not required for aggressive scanning
			sys.exit(1)

		if(not args.domain):
			s = ldap3.Server(args.domain_controller_ip, get_info = ldap3.ALL)
			c = ldap3.Connection(s)
			if(not c.bind()):
				print(c.result)
				print("Could not get domain automatically")
			else:
				try:
					args.domain = s.info.other["ldapServiceName"][0].split("@")[1]
				except Exception as e:
					print(e)
					print("Could not get domain automatically")
			c.unbind()


		# Definetely feel like this could be more effienct, but ipv6 support is throwing me off from using bitmask along with structs unpacking differently on different platforms? (might be a problem for dns)
		args.scopeEnabled = False
		args.scopeInclude = []
		args.scopeExclude = []
		if(args.scope):
			args.scopeEnabled = True
			scopeList = args.scope.split(",")

			for ipr in scopeList:
				if(ipr.startswith("i:")):
					args.scopeInclude.append(ipaddress.ip_network(ipr[2:]))
				elif(ipr.startswith("e:")):
					args.scopeExclude.append(ipaddress.ip_network(ipr[2:]))
				else:
					print("Invalid scope...")
					sys.exit(1)

		
		if(args.ssl):
			self.s = ldap3.Server(args.domain_controller_ip, get_info=ldap3.ALL, use_ssl=True)
		else:
			self.s = ldap3.Server(args.domain_controller_ip, get_info=ldap3.ALL)

		if(args.hash):
			self.c = ldap3.Connection(self.s, f"{args.domain}\\{args.username}", args.hash, authentication="NTLM")
			args.password = args.hash
		elif(args.password != ''):
			self.c = ldap3.Connection(self.s, f"{args.domain}\\{args.username}", args.password, authentication="NTLM")
		else:
			self.c = ldap3.Connection(self.s)
			
		if(not self.c.bind()):
			print(self.c.result)
			sys.exit(1)


		## Setup
		args.default_search_base = s.info.other.get('DefaultNamingContext')[0]

		args.save_dir = "".join(c for c in args.domain if c.isalnum() or c in [' ', '.', '_']).rstrip()

		os.makedirs(f"{args.save_dir}/full", exist_ok=True)
		os.makedirs(f"{args.save_dir}/saves", exist_ok=True)

		

		### Header continued
		print("")
		print(f"{bcolors.BOLD}Target Information{bcolors.ENDC}")
		print("=========================")
		print(f"Domain Controller: {args.domain_controller_ip}")
		print(f"Domain: {args.domain}")
		print(f"Default Context: {args.default_search_base}")
		print(f"Username: {args.username}")
		if(args.hash):
			print(f"Hash: {args.password}")
		else:
			print(f"Password: {args.password}")
		print(f"Output Folder: {args.save_dir}")
		if(args.scopeEnabled):
			print(f"Scope: {args.scope}")
		else:
			print(f"Scope: Ask")
		print("")


## TODOLIST
# TODO LDAP searchs are fetching deactivated accounts, maybe mark them as such
# TODO CME along with others will break if there are no routes to services, ie dc01.inlane.htb is not in /etc/hosts

if __name__ == "__main__":
	adhunt = AD_Hunt()
	adhunt.run()