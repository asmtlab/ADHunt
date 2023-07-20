#!/usr/bin/python3

import ldap3
from ldap3 import *
import sys
import os
import argparse
from dns_structures import *
from impacket.ldap import ldaptypes
import dns.resolver
import ipaddress
import textwrap


class RawFormatter(argparse.HelpFormatter):
    def _fill_text(self, text, width, indent):
        return "\n".join([textwrap.fill(line, width) for line in textwrap.indent(textwrap.dedent(text), indent).splitlines()])

class AD_Hunt:
	# colors from https://gist.github.com/nazwadi/ca00352cd0d20b640efd
	class bcolors:
		PURPLE = '\033[95m'
		OKBLUE = '\033[94m'
		OKCYAN = '\033[96m'
		OKGREEN = '\033[92m'
		WARNING = '\033[93m'
		FAIL = '\033[91m'
		ENDC = '\033[0m'
		BOLD = '\033[1m'
		UNDERLINE = '\033[4m'
		INSTALL = '\x1B[38;5;166m'
		CMD = '\x1B[38;5;151m'
		HELPEXAMPLE = '\x1B[38;5;220m'
		HELPHIGHLIGHT = '\x1B[38;5;128m'

	"""
	Fetches password policies and prints them to the screen color coded by security.  Specifically it 
	fetches Minimum password length, Password History Length, Password Complexity Bit, Lockout Threshold, 
	Lockout Duration, and checks if LAPS is in use.

	Num of LDAP queries: 2
	Created files: 0
	"""
	def passwordPolicies(self):
		args = self.args
		c = self.c
		s = self.s
		
		print("")
		print(f"{self.bcolors.BOLD}Password Policies{self.bcolors.ENDC}")
		print("=========================")
		print("")

		#### borrowed from: https://github.com/yaap7/ldapsearch-ad
		### default password policies LDAP 									(objectClass=domainDNS)
		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(objectClass=domainDNS)', search_scope=ldap3.SUBTREE, attributes=['minPwdLength','pwdHistoryLength','pwdProperties','lockoutThreshold','lockoutDuration'], generator=False)

		for resp in c.response:
			if resp['type'] == 'searchResEntry':
				minPwd = resp['attributes']['minPwdLength']
				hisLen = resp['attributes']['pwdHistoryLength']
				compBit = resp['attributes']['pwdProperties'] & 1 > 0
				lthres = resp['attributes']['lockoutThreshold']
				ldur = resp['attributes']['lockoutDuration']

		if(minPwd < 15):
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Password Minimum Length: {self.bcolors.FAIL}{minPwd}{self.bcolors.ENDC}")
		else:
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Password Minimum Length: {self.bcolors.OKGREEN}{minPwd}{self.bcolors.ENDC}")

		if(hisLen <= 2):
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Password History Length: {self.bcolors.FAIL}{hisLen}{self.bcolors.ENDC}")
		else:
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Password History Length: {self.bcolors.OKGREEN}{hisLen}{self.bcolors.ENDC}")

		if(compBit == False):
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Password Complexity Bit Set: {self.bcolors.FAIL}False{self.bcolors.ENDC}")
		else:
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Password Complexity Bit Set: {self.bcolors.OKGREEN}True{self.bcolors.ENDC}")

		if(lthres == 0):
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Lockout Threshold: {self.bcolors.FAIL}False{self.bcolors.ENDC}")
		else:
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Lockout Threshold: {self.bcolors.FAIL}{lthres}{self.bcolors.ENDC}")

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Lockout Duration: {ldur}")



		### fine grain password policies LDAP 									(objectClass=MsDS-PasswordSettings)

		##### LAPS in use? Every user should be able to see the AdmPwdExpiration attribute			Check for 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=DOMAIN' DOMAIN schema should be in s.info
		laps_use = c.extend.standard.paged_search(search_base=s.info.other.get('SchemaNamingContext')[0], search_filter='(cn=ms-mcs-AdmPwdExpirationTime)', search_scope=ldap3.SUBTREE, attributes="name", generator=False)

		if(len(laps_use) > 0):
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} LAPS installed: {self.bcolors.OKGREEN}True{self.bcolors.ENDC}")
		else:
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} LAPS installed: {self.bcolors.FAIL}False{self.bcolors.ENDC}")
		
		print("")

	"""
	This searches for DNS Records that are saved in Active directory.  It outputs all records to a 
	file and returns A records and NS records. It outputs the amount of records found per zone to screen.
	
	Num of LDAP queries: 3 + O(n)
	Created files: 1

	# TODO LIST
	# - IPv6 records and scope checking support
	# - stealthy mode to cut down noise -> check less zones
	"""
	def ADDNSEnumeration(self):
		args = self.args
		s = self.s
		c = self.c
		
		print("")
		print(f"{self.bcolors.BOLD}AD DNS Enumeration{self.bcolors.ENDC}")
		print("=========================")
		print("")

		# alot borrowed from adidnsdump, but updated to include more DNS record types
		domainroot = s.info.other['defaultNamingContext'][0]
		forestroot = s.info.other['rootDomainNamingContext'][0]

		zones = set()

		c.extend.standard.paged_search(search_base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'], generator=False)

		for entry in c.response:
			if entry['type'] != 'searchResEntry':
				continue

			zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}")


		c.extend.standard.paged_search(search_base=f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'], generator=False)

		for entry in c.response:
			if entry['type'] != 'searchResEntry':
				continue

			zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}")

		c.extend.standard.paged_search(search_base=f"CN=MicrosoftDNS,CN=System,{domainroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'], generator=False)

		for entry in c.response:
			if entry['type'] != 'searchResEntry':
				continue

			zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,CN=System,{domainroot}")

		# we need to save some records in memory for use in converting domain controllers to ips
		A_records = [] # IPv4 to DNS records
		NS_records = [] # namesever records

		with open(f"{args.save_dir}/ad_dns_dump.txt", "w") as f:
			for zone in zones:
				num_records = 0
				f.write(zone)
				f.write("\n\n")
				c.extend.standard.paged_search(f'{zone}', "(objectClass=*)", search_scope=LEVEL, attributes=['dnsRecord','dNSTombstoned','name'], paged_size=500, generator=False)
				
				for entry in c.response:
					if entry['type'] != 'searchResEntry':
						f.write(str(entry))
						f.write("\n")
						continue
				
					for record in entry["raw_attributes"]["dnsRecord"]:
						dr = DNS_RECORD(record)
						num_records += 1

						queryType = RECORD_TYPE_MAPPING[dr['Type']]
						recordname = entry["attributes"]["name"]
						
						# spent too many hours looking at this already, you can add types from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ac793981-1c60-43b8-be59-cdbb5c4ecb8a
						# identification for all record types is already configured, just not structures and exporting
						if queryType == 'ZERO':
							data = DNS_RPC_RECORD_TS(dr["Data"])
							f.write(str({'name': recordname, 'type': queryType, 'value': data.dump()}))
							f.write("\n")
						elif queryType == 'A':
							data = DNS_RPC_RECORD_A(dr["Data"])
							record_mapped = {'name':recordname, 'type': queryType, 'value': data.formatCanonical()}
							A_records.append(record_mapped)
							f.write(str(record_mapped))
							f.write("\n")
						elif queryType in ['PTR', 'CNAME']:
							data = DNS_RPC_RECORD_NODE_NAME(dr["Data"])
							f.write(str({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[0]].toFqdn()}))
							f.write("\n")
						elif queryType == 'NS':
							data = DNS_RPC_RECORD_NODE_NAME(dr["Data"])
							NS_records.append({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[0]].toFqdn()})
							f.write(str({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[0]].toFqdn()}))
							f.write("\n")
						elif queryType == 'TXT':
							data = DNS_RPC_RECORD_STRING(dr["Data"])
							f.write(str({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[0]]}))
							f.write("\n")               
						elif queryType == 'SRV':
							data = DNS_RPC_RECORD_SRV(dr["Data"])
							f.write(str({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[3]].toFqdn()}))
							f.write("\n")
						elif queryType == 'AAAA':
							data = DNS_RPC_RECORD_AAAA(dr["Data"])
							f.write(str({'name':recordname, 'type': queryType, 'value': data.formatCanonical()}))
							f.write("\n")
						else:
							f.write("=======UNKNOWN DNS RECORD=======\n")
							f.write(f'name: {recordname}, type: {queryType}\n')
							f.write('Dump: ')
							f.write(str(dr.getData()))
							f.write("\n")
							f.write("================================\n")
				
				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found zone: {zone}: with {num_records} records")			

		print("")
		print(f"AD DNS Dumping saved to {args.save_dir}/ad_dns_dump.txt")
		print("")

		return NS_records, A_records

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
	def NSEnumeration(self, NS_records: list, A_records: list):
		args = self.args
		c = self.c
		s = self.s
		
		print("")
		print(f"{self.bcolors.BOLD}NameServer Enumeration{self.bcolors.ENDC}")
		print("=========================")
		print("")


		dns_resolver = dns.resolver.Resolver(configure=False)
		dns_resolver.nameservers = []

		# add all name servers that we have ips for to our dns resolver
		ns_processed = []
		for ns in NS_records:
			if(args.domain.lower() in ns["value"].lower()): # does the dns server sit within the domain we are scanning
						
				if(ns['value'] in ns_processed):
					continue

				ns_processed.append(ns['value'])

				if(not args.scopeEnabled): # if scope is enabled we will just check if the nameserver is in scope then use it if it is.
					use_name = input(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found Nameserver {ns['value']}, use this (Y/n): ")
					if(not "Y" in use_name and not "y" in use_name):
						continue

				# DNS records in AD are stored at the subdomain component so we need to fetch that
				query = ns["value"].split(args.domain.lower())[0] #is this a subdomain  [dc01].inlanefrieght.htb.
				if(query == "." or query == ""):
					query = '@'
				else:
					query = query[:-1]
					

				matching_ips = set()
				for a in A_records:
					if(a["name"].lower() == query):
						matching_ips.add(a["value"])


				for ip in matching_ips:
					if(args.scopeEnabled):
						if(self.checkScope(ip)):
							dns_resolver.nameservers.append(ip)
					else:
						use = input(f"[?] Found IP: {ip} for {ns['value']}. Use this IP (Y/n): ")
						if("Y" in use or "y" in use):
							dns_resolver.nameservers.append(ip)

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Name Servers have been set as {dns_resolver.nameservers}")

		return dns_resolver

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
	def DCEnumeration(self, A_records: list):
		
		args = self.args
		c = self.c
		s = self.s

		print("")
		print(f"{self.bcolors.BOLD}Domain Controller Identification{self.bcolors.ENDC}")
		print("=========================")
		print("")
		# get all NTDSDSA objects, only domain controllers run this service
		c.extend.standard.paged_search(search_base=s.info.other.get('ConfigurationNamingContext')[0], search_filter='(objectClass=nTDSDSA)', search_scope=ldap3.SUBTREE, attributes=["distinguishedName"], generator=False)

		dc_ip = set()

		results = c.response 
		for i in range(len(results)):
			if(results[i]["type"] == "searchResEntry"):
				dName = results[i]["attributes"]["distinguishedName"]

				objectBase = dName[dName.index(",")+1:] # get the Parent CN=Child,CN=Parent,....DC=EXAMPLE,DC=NET

				c.extend.standard.paged_search(search_base=objectBase, search_filter='(objectClass=*)', search_scope=ldap3.BASE, attributes=["name"], generator=False)

				#should only return one response if we did it right
				domain_controller_name = c.response[0]['attributes']['name']

				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found {domain_controller_name}")

				# prevents duplicates in a messy way
				vals = list(set([x["value"] for x in A_records if x["name"].lower() == domain_controller_name.lower()]))

				if(len(vals) == 0):
					print(f"DNS search revealed no IPs for {domain_controller_name}")
					print("Skipping Vuln testing for this DC")
					continue
				
				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} AD DNS search revealed the following Domain Controller: {domain_controller_name}")
				
				if(args.scopeEnabled):
					for ip in vals:
						if(self.checkScope(ip)):
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
		
		dc_ip.add(args.domain_controller_ip)
		return dc_ip

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
	def systemEnumeration(self, A_records: list, dns_resolver):
		args = self.args
		c = self.c
		s = self.s

		print("")
		print(f"{self.bcolors.BOLD}System Enumeration{self.bcolors.ENDC}")
		print("=========================")
		print("")

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Finding IPs to scan")

		system_ips = set()
		seen_ips = set()

		# LinWinPwn uses the adinaddump service to find ips, we will use 2 methods

		# Method 1: search our previously obtained A records for IPS
		for a in A_records:
			if(a['value'] in seen_ips):
				continue
			seen_ips.add(a['value'])
			if(args.scopeEnabled):
				if(self.checkScope(a['value'])):
					system_ips.add(a['value'])
			else:
				ip_dns = input(f"[?] AD-DNS found ip: {a['value']}, scan this IP (y/n): ")
				if("Y" in ip_dns or "y" in ip_dns):
					system_ips.add(a['value'])

		# Method 2: Check for services running and ask the DNS servers we found to get us an ip for the services
		# resolver should already be setup
		print("Checking for services")

		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(dnshostname=*)', search_scope=ldap3.SUBTREE, attributes=["dnshostname"], generator=False)

		for section in c.response:
			if(section["type"] == "searchResEntry"):
				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found service: {section['attributes']['dnshostname']}")

				# try and resolve these to ips with our resolver
				try:
					ans = dns_resolver.resolve(section['attributes']['dnshostname'], 'A')
				except:
					print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} Could not resolve {section['attributes']['dnshostname']}.")
					continue

				for response in ans:
					if(response.to_text() in seen_ips):
						continue
					seen_ips.add(response.to_text())
					
					if(args.scopeEnabled):
						if(self.checkScope(response.to_text())):
							system_ips.add(response.to_text())
					else:
						ip_dns = input(f"[?] DNS Resolved an IP {response.to_text()}, use this IP (y/n): ")
						if("Y" in ip_dns or "y" in ip_dns):
							system_ips.add(response.to_text())
		
		system_ips.add(args.domain_controller_ip)
		return system_ips
	
	"""
	This checks a list of ips for vulnerabilities. Namely: smb_signing, webdav, and printspooler. In the
	case where the ip appears in the domain controller list it also checks for ldap_signing, petitpotam, eternalblue, 
	dfscoerce, zerologon (work in progress), and nopac. This also can be very noisy.

	Num of LDAP queries: 1
	Created files: 0
	"""
	def systemVulncheck(self, system_ips: list, dc_ip: list):
		args = self.args

		print("")
		print(f"{self.bcolors.BOLD}Systems Vulnerability Checks{self.bcolors.ENDC}")
		print("=========================")
		print("")

		if(len(system_ips) > 0):
			print(f"Running checks for {len(system_ips)} systems")
			print("")

		pHVal = "-p" 
		if(args.hash):
			pHVal = "-H"

		# remember pass = hash in the case where the hash is set

		for ip in system_ips:

			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} WebDav Scan for {ip}")
			if(args.quiet):
				ret = os.popen(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}'  -M webdav").read()
				if("Service enabled" in ret):
					print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.WARNING}WebDav/WebClient service enabled{self.bcolors.ENDC}")
			else:
				os.system(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M webdav")



			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} Spooler Scan for {ip}")
			if(args.quiet):
				ret = os.popen(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}'  -M spooler").read()
				if("Spooler service enabled" in ret):
					print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.WARNING}Spooler service enabled{self.bcolors.ENDC}")
			else:
				os.system(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}'  -M spooler")

			if(ip in dc_ip):
				print("")
				print(f"{self.bcolors.INSTALL}[!]{self.bcolors.ENDC} {ip} is a domain controller, running extra checks")
				print("")

				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} LDAP Signing Scan for {ip}, as {args.username}")
				if(args.quiet):
					ret = os.popen(f"crackmapexec ldap {ip} -u '{args.username}' {pHVal} '{args.password}' -M ldap-checker").read()
					if("VULNERABLE" in ret):
						print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.FAIL}Vulnerable{self.bcolors.ENDC}")
				else:
					os.system(f"crackmapexec ldap {ip} -u '{args.username}' {pHVal} '{args.password}' -M ldap-checker")


				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} Petitpotam Scan for {ip}")
				if(args.quiet):
					ret = os.popen(f"crackmapexec smb {ip} -u '' -p '' -M petitpotam").read()
					if("VULNERABLE" in ret):
						print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.FAIL}Vulnerable{self.bcolors.ENDC}")
				else:
					os.system(f"crackmapexec smb {ip} -u '' -p '' -M petitpotam")


				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} Credentialed Petitpotam Scan for {ip}")
				if(args.quiet):
					ret = os.popen(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M petitpotam").read()
					if("VULNERABLE" in ret):
						print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.FAIL}Vulnerable{self.bcolors.ENDC}")
				else:
					os.system(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M petitpotam")

				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} EternalBlue Scan for {ip}")
				if(args.quiet):
					ret = os.popen(f"crackmapexec smb {ip} -u '' -p '' -M ms17-010").read()
					if("VULNERABLE" in ret):
						print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.FAIL}Vulnerable{self.bcolors.ENDC}")
				else:
					os.system(f"crackmapexec smb {ip} -u '' -p '' -M ms17-010")

				
				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} DFSCoerce Scan for {ip}")
				if(args.quiet):
					ret = os.popen(f"crackmapexec smb {ip} -u '' -p '' -M dfscoerce").read()
					if("VULNERABLE" in ret):
						print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.FAIL}Vulnerable{self.bcolors.ENDC}")
				else:
					os.system(f"crackmapexec smb {ip} -u '' -p '' -M dfscoerce")

				
				""" TODO Zerologon is broken and does not close crackmapexec after completing """
				""" print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} Zerologon Scan for {domain_controller_name}")
				os.system(f"crackmapexec smb {vals[selected_ip]} -u '' -p '' -M zerologon")
				os.system(f"pkill crackmapexec")
				print("") """

				print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} NoPac Scan for {ip}, as {args.username}")
				if(args.quiet):
					ret = os.popen(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M nopac").read()
					if("VULNERABLE" in ret):
						print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {self.bcolors.FAIL}Vulnerable{self.bcolors.ENDC}")
				else:
					os.system(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M nopac")

			print("")
	"""
	This simply just uses certipy to find all vulnerable certicates within a domain.

	Num of LDAP queries: ?
	Created files: 3
	"""
	def certificateEnumeration(self):
		args = self.args

		print("")
		print(f"{self.bcolors.BOLD}Certificate Services{self.bcolors.ENDC}")
		print("=========================")
		print("")

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Scanning with {self.bcolors.PURPLE}CERTIPY{self.bcolors.ENDC}")

		pHVal = '-p'
		if(args.hash):
			pHVal = '-hashes'
		
		if(args.quiet):
			ret = os.popen(f"certipy-ad find -u '{args.username}@{args.domain}' {pHVal} '{args.password}' -target-ip '{args.domain_controller_ip}' -dc-ip '{args.domain_controller_ip}' -vulnerable -output {args.save_dir}/").read()
			matched_lines = [line for line in ret.split('\n') if "failed" in line.lower()]
			for line in matched_lines:
				print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} {line[4:]}")

			print("")
			print(f"Files saved in {args.save_dir} as Certipy.*")
		else:
			os.system(f"certipy-ad find -u '{args.username}@{args.domain}' {pHVal} '{args.password}' -target-ip '{args.domain_controller_ip}' -dc-ip '{args.domain_controller_ip}' -vulnerable -output {args.save_dir}/")

	"""
	This enumerates users in the active directory instance who have a description linked to their account or
	who do not require a password. It also performs kerberoasting and asreproasting attacks.

	Num of LDAP queries: 2 + ?
	Created files: 4

	# TODO LIST
	# - rewrite roasting attacks to remove dependance on CME
	"""
	def userEnumeration(self):
		args = self.args
		c = self.c

		### User Enumerations
		print("")
		print(f"{self.bcolors.BOLD}User Enumerations{self.bcolors.ENDC}")
		print("=========================")
		print("")

		##### Users with descriptions -> output to file (print number found)					(&(objectClass=user)(description=*))
		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(&(objectClass=user)(description=*))', search_scope=ldap3.SUBTREE, attributes=["name", "description"], generator=False)

		count = 0
		with open(f"{args.save_dir}/full/users_dcsrp_full.txt", "w") as f:
			f.write(str(c.response))
			
		with open(f"{args.save_dir}/users_dcsrp.txt", "w") as f:
			for i in range(len(c.response)):
				if(c.response[i]["type"] == "searchResEntry"):
					f.write(str(c.response[i]["attributes"]["name"]) + ": " + str(c.response[i]["attributes"]["description"]) + "\n")
					count += 1

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found {count} users with descriptions")


		##### Users without a password set -> output to file (print number found)				(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))

		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))', search_scope=ldap3.SUBTREE, attributes=["name"], generator=False)

		count = 0
		with open(f"{args.save_dir}/users_no_req_pass.txt", "w") as f:
			for i in range(len(c.response)):
				if(c.response[i]["type"] == "searchResEntry"):
					f.write(str(c.response[i]["attributes"]["name"]) + "\n")
					count += 1
			
		with open(f"{args.save_dir}/full/users_no_req_pass_full.txt", "w") as f:
			f.write(str(c.response))
			
		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found {count} users without required passwords")



		##### Users where ASP-REP roasting is possible
		####### Retrieve tickets -> output to file
		# TODO Make sure that there is a route to the nameserver (ie, cme needed dc01.inlanefreight.htb in /etc/hosts to work)
		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Performing {self.bcolors.PURPLE}CME{self.bcolors.ENDC} ASREProasting (output hidden)")  
		if(args.hash):
			os.system(f"crackmapexec ldap {args.domain_controller_ip} -u {args.username} -H {args.hash} --asreproast {args.save_dir}/users_asreproast.txt > /dev/null")
		else:	
			os.system(f"crackmapexec ldap {args.domain_controller_ip} -u {args.username} -p {args.password} --asreproast {args.save_dir}/users_asreproast.txt > /dev/null")

		######## Option to crack hashes in background

		##### Users where Kerberoasting is possible
		####### Retrieve tickets -> output to file

		# TODO same issue as above
		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Performing {self.bcolors.PURPLE}CME{self.bcolors.ENDC} kerberoasting (output hidden)")  
		if(args.hash):
			os.system(f"crackmapexec ldap {args.domain_controller_ip} -u {args.username} -H {args.hash} --kerberoasting {args.save_dir}/users_kerberoasting.txt > /dev/null")
		else:
			os.system(f"crackmapexec ldap {args.domain_controller_ip} -u {args.username} -p {args.password} --kerberoasting {args.save_dir}/users_kerberoasting.txt > /dev/null")

		######## Option to crack hashes in background?

		print("")
		print(f"Files saved in {args.save_dir} as users_*.txt")

	"""
	This enumerates the types of delegations that are available to each object in the AD

	Num of LDAP queries: 4
	Created files: 4

	# TODO LIST
	# - condense
	"""
	def delegationEnumeration(self):
		args = self.args
		c = self.c

		print("")
		print(f"{self.bcolors.BOLD}Delegation Enumeration{self.bcolors.ENDC}")
		print("=========================")
		print("")


		##### All objects with trusted for delegation -> output to file     					(userAccountControl:1.2.840.113556.1.4.803:=524288)
		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', search_scope=ldap3.SUBTREE, attributes=["samaccountname"], generator=False)

		with open(f"{args.save_dir}/full/objects_unconstrained_delegation_full.txt", "w") as f:
			f.write(str(c.response))
			
		count = 0
		with open(f"{args.save_dir}/delegation_unconstrained_objects.txt", "w") as f:
			for i in range(len(c.response)):
				if(c.response[i]["type"] == "searchResEntry"):
					f.write(str(c.response[i]["attributes"]["samaccountname"]) + "\n")
					count += 1

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found: {count} AD Objects with Unconstrained Delegations")


		##### All objects with trusted for auth delegation -> output to file     					(userAccountControl:1.2.840.113556.1.4.803:=16777216)
		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(msDS-AllowedToDelegateTo=*)', search_scope=ldap3.SUBTREE, attributes=["useraccountcontrol","samaccountname","msDS-AllowedToDelegateTo"], generator=False)

		with open(f"{args.save_dir}/full/objects_constrained_delegation_full.txt", "w") as f:
			f.write(str(c.response))
			
		countC = 0
		countCPT = 0
		with open(f"{args.save_dir}/delegation_constrained_objects.txt", "w") as f1:
			with open(f"{args.save_dir}/delegation_constrained_w_protocol_transition_objects.txt", "w") as f2:
				f1.write("SamAccountName: {objects that account can delegate for}\n")
				f1.write("====================================================================\n")

				f2.write("SamAccountName: {objects that account can delegate for}\n")
				f2.write("====================================================================\n")
				for i in range(len(c.response)):
					if(c.response[i]["type"] == "searchResEntry"):
						if(int(c.response[i]["attributes"]["useraccountcontrol"]) & 16777216):
							f2.write(str(c.response[i]["attributes"]["samaccountname"]) + ": " + str(c.response[i]["attributes"]["msDS-AllowedToDelegateTo"]) + "\n")
							countCPT += 1
						else:
							f2.write(str(c.response[i]["attributes"]["samaccountname"]) + ": " + str(c.response[i]["attributes"]["msDS-AllowedToDelegateTo"]) + "\n")
							countC += 1

		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found: {countC} AD Objects with Constrained Delegations")
		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found: {countCPT} AD Objects with Constrained Delegations with Protocol Transition")


		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)', search_scope=ldap3.SUBTREE, attributes=["samaccountname","msDS-AllowedToActOnBehalfOfOtherIdentity"], generator=False)

		with open(f"{args.save_dir}/full/objects_rbcd_delegation_full.txt", "w") as f:
			f.write(str(c.response))
			
		count = 0
		with open(f"{args.save_dir}/delegation_rbcd_objects.txt", "w") as f:
			for i in range(len(c.response)):
				if(c.response[i]["type"] == "searchResEntry"):
					name = str(c.response[i]["attributes"]["samaccountname"])

					sF = '(|'
					sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(c.response[i]["attribute"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]))
					for ace in sd['Dacl'].aces:
						sF = sF + "(objectSid="+ace['Ace']['Sid'].formatCanonical()+")"
					sF = sF + ')'

					c.extend.standard.paged_search(search_base=args.default_search_base, search_filter=sF, search_scope=ldap3.BASE, attributes="*")

					for dele in c.response:
						f.write(f"{name} ::: delegates ::: {dele['attributes']['sAMAccountName']}\n")
						count += 1

		c.extend.standard.paged_search(search_base=args.default_search_base, search_filter='(ms-DS-MachineAccountQuota=*)', search_scope=ldap3.SUBTREE, attributes=["ms-DS-MachineAccountQuota"], generator=False)


		print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Found: {count} AD Objects with Resource Based Constrained Delegations")

		for resp in c.response:
			if(resp['type'] == "searchResEntry"):
				macctq = resp['attributes']['ms-DS-MachineAccountQuota']
				break

		if(macctq <= 0):
			print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} Machine Account Quota: {self.bcolors.OKGREEN}{macctq}{self.bcolors.ENDC}")
		else:
			print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} Machine Account Quota: {self.bcolors.FAIL}{macctq}{self.bcolors.ENDC}")


		print("")
		print(f"Files saved in {args.save_dir} as delegation_*.txt")

		print("")

	"""
	Handles checking for smb misconfigurations and does enumeration by share spidering

	Num of LDAP queries: 0
	Created files: O(n)
	"""
	def smbEnumeration(self, system_ips: list):
		args = self.args

		print("")
		print(f"{self.bcolors.BOLD}SMB Enumeration{self.bcolors.ENDC}")
		print("=========================")
		print("")

		pHVal = "-p"
		if(args.hash):
			pHVal = "-H"

		for ip in system_ips:
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Check for {ip}")

			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}NMAP{self.bcolors.ENDC} SMB Signing Scan for {ip}")
			if(args.quiet):
				ret = os.popen(f"nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 {ip}").read()
				try:
					print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} " + ret.split("|_")[1].split("\n")[0].strip())
				except:
					print(f"{self.bcolors.INSTALL}[*]{self.bcolors.ENDC} It appears SMB is not enabled on {ip}:445")
			else:
				os.system(f"nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 {ip}")

			# Share spidering
			print(f"{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Runinng {self.bcolors.PURPLE}CME{self.bcolors.ENDC} Share spider for {ip}")
			if(args.quiet):
				ret = os.popen(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M spider_plus -o OUTPUT={args.save_dir}/smb").read()
			else:
				os.system(f"crackmapexec smb {ip} -u '{args.username}' {pHVal} '{args.password}' -M spider_plus -o OUTPUT={args.save_dir}/smb")
			
		print("")
		print(f"Files saved in {args.save_dir}/smb as [ip].txt")

	"""
	This runs system commands to install the dependancies needed for this program
	"""
	def install(self):
		print("Installing... (are you root?)")
		print(f"{self.bcolors.INSTALL}{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Installing pip3{self.bcolors.ENDC}")
		os.system("apt install python3-pip")
		print(f"{self.bcolors.INSTALL}{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Installing Impacket{self.bcolors.ENDC}")
		os.system("pip3 install impacket")
		print(f"{self.bcolors.INSTALL}{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Installing CME{self.bcolors.ENDC}")
		os.system("apt install crackmapexec")
		print(f"{self.bcolors.INSTALL}{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Installing Certipy{self.bcolors.ENDC}")
		os.system("apt install certipy-ad")
		print(f"{self.bcolors.INSTALL}{self.bcolors.INSTALL}[+]{self.bcolors.ENDC} Installing NMAP{self.bcolors.ENDC}")
		os.system("apt install nmap")
		sys.exit(0)
	
	"""
	runs the check functions
	"""
	def run(self):
		args = self.args
		# Run scans


		if(not args.just or "pass-pols" in args.just):
			self.passwordPolicies()
		if(not args.just or "delegations" in args.just):
			self.delegationEnumeration()
		if(not args.just or "users" in args.just):
			self.userEnumeration()
		if(not args.just or "certificates" in args.just):
			self.certificateEnumeration()
		if(not args.just or any(x in ['ad-dns', 'nameservers', 'domain-controllers', 'systems', 'system-vulns', 'smb'] for x in args.just)):
			ns_r, a_r = self.ADDNSEnumeration()
		if(not args.just or any(x in ['nameservers', 'domain-controllers', 'systems', 'system-vulns', 'smb'] for x in args.just)):
			dns_resolver = self.NSEnumeration(ns_r, a_r)
		if(not args.just or any(x in ['domain-controllers', 'systems', 'system-vulns', 'smb'] for x in args.just)):
			dc_ips = self.DCEnumeration(a_r)
		if(not args.just or any(x in ['systems', 'system-vulns', 'smb'] for x in args.just)):
			system_ips = self.systemEnumeration(a_r, dns_resolver) #depends on nameservers, ad-dns

		if(not args.no_scan):
			if(not args.just or 'system-vulns' in args.just):
				self.systemVulncheck(system_ips, dc_ips) #depends on systems, domain_controllers
			if(not args.just or 'smb' in args.just):
				self.smbEnumeration(system_ips)
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
		
		parser.add_argument("-s", "--scope", help=f"The scope of valid ips for checking ranges when performing vulnerability scanning and enumeration. Include ranges with i, and exclude with e. Seperate args by commas, For example a valid scope would be {self.bcolors.HELPEXAMPLE}--scope i:10.129.0.0/24,e:10.129.0.129{self.bcolors.ENDC}")
		
		parser.add_argument("--detection-mode", choices={"aggressive", "moderate", "passive", "stealthy"}, 
		      help=f"passive [default] (only scan ips found from ad dns information), moderate (scan ips from ad dns and perform regular dns enumeration), aggressive (scan everything in scope), stealthy (TODO)") #TODO
		
		parser.add_argument("-q", "--quiet", help="Don't display output from tools", action="store_true")

		parser.add_argument("--no-scan", dest="no_scan", help="Do not scan found ips for vulnerabilities", action="store_true")
		
		parser.add_argument("--no-banner", dest="no_banner", help="Do not display the banner", action='store_true')
		
		parser.add_argument("--ssl", help="Should connections be made with ssl", action='store_true')

		self.tests = ["pass-pols", "delegations", "users", "certificates", "ad-dns", "nameservers", "domain-controllers", "systems", "system-vulns", "smb"]
		parser.add_argument("--just", choices=self.tests, help="only run the specified check(s) and its required other checks", nargs="+")

		self.args = parser.parse_args()

		if(os.name != "posix"):
			print("AD Hunt only works in a linux enviroment.")
			sys.exit(1)

		if(sys.version_info[0] != 3):
			print("{0}Warning: This script has only been tested for python3{1}".format(self.bcolors.WARNING, self.bcolors.ENDC))
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
			print(rf'''{self.bcolors.OKCYAN} ______  _____       __  __  __  __  __   __  ______  
/\  __ \/\  __-.    /\ \_\ \/\ \/\ \/\ "-.\ \/\__  _\ 
\ \  __ \ \ \/\ \   \ \  __ \ \ \_\ \ \ \-.  \/_/\ \/ 
 \ \_\ \_\ \____-    \ \_\ \_\ \_____\ \_\\"\_\ \ \_\ 
  \/_/\/_/\/____/     \/_/\/_/\/_____/\/_/ \/_/  \/_/ {self.bcolors.ENDC}''')

															
		print("") 
		print("")              

		if(args.install):
			self.install()

		if(not args.domain_controller_ip):
			print("Must specify the ip of a domain controller with -dc-ip") # TODO eventually not required for aggressive scanning
			sys.exit(1)

		if(not args.domain):
			s = Server(args.domain_controller_ip, get_info = ALL)
			c = Connection(s)
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
			self.s = Server(args.domain_controller_ip, get_info=ALL, use_ssl=True)
		else:
			self.s = Server(args.domain_controller_ip, get_info=ALL)

		if(args.hash):
			self.c = Connection(self.s, f"{args.domain}\\{args.username}", args.hash, authentication="NTLM")
			args.password = args.hash
		elif(args.password != ''):
			self.c = Connection(self.s, f"{args.domain}\\{args.username}", args.password, authentication="NTLM")
		else:
			self.c = Connection(self.s)
			
		if(not self.c.bind()):
			print(self.c.result)
			sys.exit(1)


		## Setup
		args.default_search_base = s.info.other.get('DefaultNamingContext')[0]

		args.save_dir = "".join(c for c in args.domain if c.isalnum() or c in [' ', '.', '_']).rstrip()

		os.makedirs(f"{args.save_dir}/full", exist_ok=True)

		

		### Header continued
		print("")
		print(f"{self.bcolors.BOLD}Target Information{self.bcolors.ENDC}")
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


	"""
	"Private" function to verify if an ip is in scope, handles both IPv4 and IPv6
	
	Returns true if ip is in scope and false if ip is not in scope
	"""
	def checkScope(self, ipt: str):
		args = self.args
		new_ip = ipaddress.ip_address(ipt)
		for ipn in args.scopeExclude:
			if(new_ip in ipn):
				return False

		for ipn in args.scopeInclude:
			if(new_ip in ipn):
				return True
				
		return False



## TODOLIST
# TODO LDAP searchs are fetching deactivated accounts, maybe mark them as such
# TODO CME along with others will break if there are no routes to services, ie dc01.inlane.htb is not in /etc/hosts

if __name__ == "__main__":
	adhunt = AD_Hunt()
	adhunt.run()