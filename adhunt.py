#!/usr/bin/python3 -i

import ldap3
from ldap3 import *
import sys
import os
import argparse
from dns_structures import *
from impacket.ldap import ldaptypes
import dns.resolver
import ipaddress

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

parser = argparse.ArgumentParser(prog="python3 adhunt.py", description="""Active Directory Enumeration tool""")
parser.add_argument("-i", "--install", action='store_true', help="install nessecary components")
parser.add_argument("--dc-ip", dest="domain_controller_ip", help="The IP of the domain controller targeted for enumeration")
parser.add_argument("-u", "--username", help="The username of the user for enumation purposes")
parser.add_argument("-p", "--password", help="The password of the supplied user")
parser.add_argument("-d", "--domain", help="The domain of the given user")
parser.add_argument("-s", "--scope", help=f"The scope of valid ips for checking ranges when performing vulnerability scanning and enumeration. Include ranges with {bcolors.HELPHIGHLIGHT}i{bcolors.ENDC}, and exclude with {bcolors.HELPHIGHLIGHT}e{bcolors.ENDC}. Seperate args by commas, For example a valid scope would be {bcolors.HELPEXAMPLE}--scope i:10.129.0.0/24,e:10.129.0.129{bcolors.ENDC}")
parser.add_argument("--detection-mode", help=f"options: ({bcolors.HELPHIGHLIGHT}aggressive{bcolors.ENDC}, {bcolors.HELPHIGHLIGHT}moderate{bcolors.ENDC}, {bcolors.HELPHIGHLIGHT}passive{bcolors.ENDC}), default is passive (only scan ips found from ad dns information), moderate (scan ips from ad dns and perform regular dns enumeration), aggressive (scan everything in scope)")
# parser.add_argument("--ssl", help="should we try to connect with ssl")

args = parser.parse_args()



if(os.name != "posix"):
	print("AD Hunt only works in a linux enviroment.")
	sys.exit(1)

if(sys.version_info[0] != 3):
	print("{0}Warning: This script has only been tested for python3{1}".format(bcolors.WARNING, bcolors.ENDC))
	sys.exit(1)

### Header
print(rf'''{bcolors.OKCYAN} ______  _____       __  __  __  __  __   __  ______  
/\  __ \/\  __-.    /\ \_\ \/\ \/\ \/\ "-.\ \/\__  _\ 
\ \  __ \ \ \/\ \   \ \  __ \ \ \_\ \ \ \-.  \/_/\ \/ 
 \ \_\ \_\ \____-    \ \_\ \_\ \_____\ \_\\"\_\ \ \_\ 
  \/_/\/_/\/____/     \/_/\/_/\/_____/\/_/ \/_/  \/_/ {bcolors.ENDC}''')
                                                      
print("") 
print("")              

if(args.install):
	print("Installing... (are you root?)")
	print(f"{bcolors.INSTALL}{bcolors.INSTALL}[+]{bcolors.ENDC} Installing pip3{bcolors.ENDC}")
	os.system("apt install python3-pip")
	print(f"{bcolors.INSTALL}{bcolors.INSTALL}[+]{bcolors.ENDC} Installing Impacket{bcolors.ENDC}")
	os.system("pip3 install impacket")
	print(f"{bcolors.INSTALL}{bcolors.INSTALL}[+]{bcolors.ENDC} Installing CME{bcolors.ENDC}")
	os.system("apt install crackmapexec")
	print(f"{bcolors.INSTALL}{bcolors.INSTALL}[+]{bcolors.ENDC} Installing Certipy{bcolors.ENDC}")
	os.system("apt install certipy-ad")
	print(f"{bcolors.INSTALL}{bcolors.INSTALL}[+]{bcolors.ENDC} Installing NMAP{bcolors.ENDC}")
	os.system("apt install nmap")
	sys.exit(0)


# TODO most LDAP searchs will fetch deactivated accounts

if(not args.domain_controller_ip):
	print("Must specify the ip of a domain controller with -dc-ip")
	sys.exit(1)

if(args.username != None and args.password == None):
	print("If a username is supplied a password must also be supplied")
	sys.exit(1)

# TODO figure out if this is nessecary
if(args.username == None):
	print("Attempting Anoynomous Bind to ldap://" + args.domain_controller_ip)
	print("Checks are not performed")
	print("")
	s = Server(args.domain_controller_ip, get_info = ALL)
	c = Connection(s)
	if(not c.bind()):
		print(c.result)
		sys.exit(1)
	print(s.info)
	
	sys.exit(0)

if(not args.domain):
	print("A domain must be supplied.")
	sys.exit(1)

# Definetely feel like this could be more effienct, but ipv6 support is throwing me off from using bitmask along with structs unpacking differently on different platforms? (might be a problem for dns)
scopeEnabled = False
scopeInclude = []
scopeExclude = []
if(args.scope):
	scopeEnabled = True
	scopeList = args.scope.split(",")

	for ipr in scopeList:
		if(ipr.startswith("i:")):
			scopeInclude.append(ipaddress.ip_network(ipr[2:]))
		elif(ipr.startswith("e:")):
			scopeExclude.append(ipaddress.ip_network(ipr[2:]))
		else:
			print("Invalid scope...")
			sys.exit(1)

"""
Returns true if ip is in scope
returns false if ip is not in scope
"""
def checkScope(ipt: str):
	new_ip = ipaddress.ip_address(ipt)
	for ipn in scopeExclude:
		if(new_ip in ipn):
			return False

	for ipn in scopeInclude:
		if(new_ip in ipn):
			return True
		
	return False

s = Server(args.domain_controller_ip, get_info = ALL)
c = Connection(s, f"{args.domain}\\{args.username}", args.password, authentication="NTLM")

if(not c.bind()):
	print(c.result)
	sys.exit(1)

dc_informatin = s.info

## also TLS?

## Setup
default_search_base = s.info.other.get('DefaultNamingContext')[0]

save_dir = "".join(c for c in args.domain if c.isalnum() or c in [' ', '.', '_']).rstrip()

os.makedirs(f"{save_dir}/full", exist_ok=True)


### Header continued
print("")
print(f"{bcolors.BOLD}Target Information{bcolors.ENDC}")
print("=========================")
print(f"Domain Controller: {args.domain_controller_ip}, {args.domain}")
print(f"Default Context: {default_search_base}")
print(f"Username: {args.username}")
print(f"Password: {args.password}")
print(f"Output Folder: {save_dir}")
print(f"Scope: Ask")
print("")

### Password Policies
print("")
print(f"{bcolors.BOLD}Password Policies{bcolors.ENDC}")
print("=========================")
print("")

#### borrowed from: https://github.com/yaap7/ldapsearch-ad
### default password policies LDAP 									(objectClass=domainDNS)
c.extend.standard.paged_search(search_base=default_search_base, search_filter='(objectClass=domainDNS)', search_scope=ldap3.SUBTREE, attributes=['minPwdLength','pwdHistoryLength','pwdProperties','lockoutThreshold','lockoutDuration'], generator=False)

with open(f"{save_dir}/full/pass_pols.txt", "w") as f:
	f.write(str(c.response))

for resp in c.response:
	if resp['type'] == 'searchResEntry':
		minPwd = resp['attributes']['minPwdLength']
		hisLen = resp['attributes']['pwdHistoryLength']
		compBit = resp['attributes']['pwdProperties'] & 1 > 0
		lthres = resp['attributes']['lockoutThreshold']
		ldur = resp['attributes']['lockoutDuration']

if(minPwd < 15):
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Password Minimum Length: {bcolors.FAIL}{minPwd}{bcolors.ENDC}")
else:
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Password Minimum Length: {bcolors.OKGREEN}{minPwd}{bcolors.ENDC}")

if(hisLen <= 2):
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Password History Length: {bcolors.FAIL}{hisLen}{bcolors.ENDC}")
else:
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Password History Length: {bcolors.OKGREEN}{hisLen}{bcolors.ENDC}")

if(compBit == False):
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Password Complexity Bit Set: {bcolors.FAIL}False{bcolors.ENDC}")
else:
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Password Complexity Bit Set: {bcolors.OKGREEN}True{bcolors.ENDC}")

if(lthres == 0):
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Lockout Threshold: {bcolors.FAIL}False{bcolors.ENDC}")
else:
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Lockout Threshold: {bcolors.FAIL}{lthres}{bcolors.ENDC}")

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Lockout Duration: {ldur}")



### fine grain password policies LDAP 									(objectClass=MsDS-PasswordSettings)


##### LAPS in use? Every user should be able to see the AdmPwdExpiration attribute			Check for 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=DOMAIN' DOMAIN schema should be in s.info
laps_use = c.extend.standard.paged_search(search_base=s.info.other.get('SchemaNamingContext')[0], search_filter='(cn=ms-mcs-AdmPwdExpirationTime)', search_scope=ldap3.SUBTREE, attributes="name", generator=False)

if(len(laps_use) > 0):
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} LAPS installed: {bcolors.OKGREEN}True{bcolors.ENDC}")
else:
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} LAPS installed: {bcolors.FAIL}False{bcolors.ENDC}")
print("")
print("Full password information dump saved to pass_pols.txt")
print("")

print("")
print(f"{bcolors.BOLD}AD DNS Enumeration{bcolors.ENDC}")
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
A_records = [] # probably should add support for IPv6 #TODO
NS_records = [] #

with open(f"{save_dir}/ad_dns_dump.txt", "w") as f:
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
		
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found zone: {zone}: with {num_records} records")			

print("")
print(f"AD DNS Dumping saved to {save_dir}/ad_dns_dump.txt")
print("")

print("")
print(f"{bcolors.BOLD}NameServer Enumeration{bcolors.ENDC}")
print("=========================")
print("")


# TODO Dns zone transfer, brute, exfil

dns_resolver = dns.resolver.Resolver(configure=False)
dns_resolver.nameservers = []

# add all name servers that we have ips for to our dns resolver
ns_processed = []
for ns in NS_records:
	if(args.domain in ns["value"]): # does the dns server sit within the domain we are scanning
				
		if(ns['value'] in ns_processed):
			continue

		ns_processed.append(ns['value'])

		if(not scopeEnabled): # if scope is enabled we will just check if the nameserver is in scope then use it if it is.
			use_name = input(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found Nameserver {ns['value']}, use this (Y/n): ")
			if(not "Y" in use_name and not "y" in use_name):
				continue

		# DNS records in AD are stored at the subdomain component so we need to fetch that
		query = ns["value"].split(args.domain)[0] #is this a subdomain  [dc01].inlanefrieght.htb.
		if(query == "." or query == ""):
			query = '@'
		else:
			query = query[:-1]
			
		
		matching_ips = set()
		for a in A_records:
			if(a["name"] == query):
				matching_ips.add(a["value"])

		for ip in matching_ips:
			if(scopeEnabled):
				if(checkScope(ip)):
					dns_resolver.nameservers.append(ip)
			else:
				use = input(f"[?] Found IP: {ip} for {ns['value']}. Use this IP (Y/n): ")
				if("Y" in use or "y" in use):
					dns_resolver.nameservers.append(ip)

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Name Servers have been set as {dns_resolver.nameservers}")

### Domain controllers identifications
print("")
print(f"{bcolors.BOLD}Domain Controller Identification{bcolors.ENDC}")
print("=========================")
print("")
# get all NTDSDSA objects, only domain controllers run this service
c.extend.standard.paged_search(search_base=s.info.other.get('ConfigurationNamingContext')[0], search_filter='(objectClass=nTDSDSA)', search_scope=ldap3.SUBTREE, attributes=["distinguishedName"], generator=False)

dc_ip = []

results = c.response 
for i in range(len(results)):
	if(results[i]["type"] == "searchResEntry"):
		dName = results[i]["attributes"]["distinguishedName"]

		objectBase = dName[dName.index(",")+1:] # get the Parent CN=Child,CN=Parent,....DC=EXAMPLE,DC=NET

		c.extend.standard.paged_search(search_base=objectBase, search_filter='(objectClass=*)', search_scope=ldap3.BASE, attributes=["name"], generator=False)

		#should only return one response if we did it right
		domain_controller_name = c.response[0]['attributes']['name']

		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found {domain_controller_name}")

		# prevents duplicates in a messy way
		vals = list(set([x["value"] for x in A_records if x["name"].lower() == domain_controller_name.lower()]))

		if(len(vals) == 0):
			print(f"DNS search revealed no IPs for {domain_controller_name}")
			print("Skipping Vuln testing for this DC")
			continue
		
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} AD DNS search revealed the following Domain Controller {domain_controller_name}")
		
		if(scopeEnabled):
			for ip in vals:
				if(checkScope(ip)):
					dc_ip.append(ip)
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
				dc_ip.append(vals[selected_ip])



print("")
print(f"{bcolors.BOLD}System Scanning{bcolors.ENDC}")
print("=========================")
print("")

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Finding IPs to scan")

system_ips = set()
seen_ips = set()

# LinWinPwn uses the adinaddump service to find ips, we will use 2 methods

# Method 1: search our previously obtained A records for IPS
for a in A_records:
	if(a['value'] in seen_ips):
		continue
	seen_ips.add(a['value'])
	if(scopeEnabled):
		if(checkScope(a['value'])):
			system_ips.add(a['value'])
	else:
		ip_dns = input(f"[?] AD-DNS found ip: {a['value']}, scan this IP (y/n): ")
		if("Y" in ip_dns or "y" in ip_dns):
			system_ips.add(a['value'])

# Method 2: Check for services running and ask the DNS servers we found to get us an ip for the services
# resolver should already be setup
print("Checking for services")

c.extend.standard.paged_search(search_base=default_search_base, search_filter='(dnshostname=*)', search_scope=ldap3.SUBTREE, attributes=["dnshostname"], generator=False)

for section in c.response:
	if(section["type"] == "searchResEntry"):
		print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found service: {section['attributes']['dnshostname']}")

		# try and resolve these to ips with our resolver
		try:
			ans = dns_resolver.query(section['attributes']['dnshostname'], 'A')
		except:
			print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Could not resolve domain.")
			continue

		for response in ans:
			if(response.to_text() in seen_ips):
				continue
			seen_ips.add(response.to_text())
			
			if(scopeEnabled):
				if(checkScope(response.to_text())):
					system_ips.add(response.to_text())
			else:
				ip_dns = input(f"[?] DNS Resolved an IP {response.to_text()}, use this IP (y/n): ")
				if("Y" in ip_dns or "y" in ip_dns):
					system_ips.add(response.to_text())

if(len(system_ips) > 0):
	print("")
	print(f"Running checks for {system_ips}")
	print("")

for ip in system_ips:
	print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Check for {ip}")

	print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}NMAP{bcolors.ENDC} SMB Signing Scan for {ip} ")
	os.system(f"nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 {ip}")
	print("")

	#Auth reliant
	print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} WebDav Scan for {ip}")
	os.system(f"crackmapexec smb {ip} -u '{args.username}' -p '{args.password}'  -M webdav")
	print("")

	print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} Spooler Scan for {ip}")
	os.system(f"crackmapexec smb {ip} -u '{args.username}' -p '{args.password}'  -M spooler")
	print("")

	if(ip in dc_ip):
			print(f"{bcolors.INSTALL}[!]{bcolors.ENDC} {ip} is a domain controller, running extra checks")
			print("")
			print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} LDAP Signing Scan for {domain_controller_name}, with creds {args.username}:{args.password}")
			os.system(f"crackmapexec ldap {ip} -u '{args.username}' -p '{args.password}' -M ldap-checker")
			print("")

			print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} Petitpotam Scan for {domain_controller_name}")
			os.system(f"crackmapexec smb {ip} -u '' -p '' -M petitpotam")
			print("")
			
			print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} EternalBlue Scan for {domain_controller_name}")
			os.system(f"crackmapexec smb {ip} -u '' -p '' -M ms17-010")
			print("")
			
			print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} DFSCoerce Scan for {domain_controller_name}")
			os.system(f"crackmapexec smb {ip} -u '' -p '' -M dfscoerce")
			print("")
			
			""" TODO Zerologon is broken and does not close crackmapexec after completing """
			""" print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} Zerologon Scan for {domain_controller_name}")
			os.system(f"crackmapexec smb {vals[selected_ip]} -u '' -p '' -M zerologon")
			os.system(f"pkill crackmapexec")
			print("") """
			
			#TODO this is dependant on authentication type
			print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Runinng {bcolors.PURPLE}CME{bcolors.ENDC} NoPac Scan for {domain_controller_name}, with creds {args.username}:{args.password}")
			os.system(f"crackmapexec smb {ip} -u '{args.username}' -p '{args.password}' -M nopac")
			print("")


print("")
print(f"{bcolors.BOLD}Certificate Services{bcolors.ENDC}")
print("=========================")
print("")

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Scanning with certipy-ad")
#TODO Different auth types
#TODO often certipy finds the wrong ip for connecting too
os.system(f"certipy-ad find -u '{args.username}@{args.domain}' -p '{args.password}' -target-ip '{args.domain_controller_ip}' -dc-ip '{args.domain_controller_ip}' -vulnerable -output {save_dir}/")


### User Enumerations
print("")
print(f"{bcolors.BOLD}User Enumerations{bcolors.ENDC}")
print("=========================")
print("")

##### Users with descriptions -> output to file (print number found)					(&(objectClass=user)(description=*))
c.extend.standard.paged_search(search_base=default_search_base, search_filter='(&(objectClass=user)(description=*))', search_scope=ldap3.SUBTREE, attributes=["name", "description"], generator=False)

count = 0
with open(f"{save_dir}/full/users_dcsrp_full.txt", "w") as f:
	f.write(str(c.response))
	
with open(f"{save_dir}/users_dcsrp.txt", "w") as f:
	for i in range(len(c.response)):
		if(c.response[i]["type"] == "searchResEntry"):
			f.write(str(c.response[i]["attributes"]["name"]) + ": " + str(c.response[i]["attributes"]["description"]) + "\n")
			count += 1

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found {count} users with descriptions")


##### Users without a password set -> output to file (print number found)				(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))

c.extend.standard.paged_search(search_base=default_search_base, search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))', search_scope=ldap3.SUBTREE, attributes=["name"], generator=False)

count = 0
with open(f"{save_dir}/users_no_req_pass.txt", "w") as f:
	for i in range(len(c.response)):
		if(c.response[i]["type"] == "searchResEntry"):
			f.write(str(c.response[i]["attributes"]["name"]) + "\n")
			count += 1
	
with open(f"{save_dir}/full/users_no_req_pass_full.txt", "w") as f:
	f.write(str(c.response))
	
print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found {count} users without required passwords")

print("")

##### Users where ASP-REP roasting is possible
####### Retrieve tickets -> output to file
# TODO Make sure that there is a route to the nameserver (ie, cme needed dc01.inlanefreight.htb in /etc/hosts to work)
# TODO change for dependance on auth method
# TODO this breaks randomly when it cannot automatically determine ip of dc (usually grabs the wrong one, same issue with certipy)
print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Performing {bcolors.PURPLE}CME{bcolors.ENDC} ASREProasting (output hidden)")  
os.system(f"crackmapexec ldap {args.domain_controller_ip} -u {args.username} -p {args.password} --asreproast {save_dir}/users_asreproast.txt > /dev/null")
print("")

######## Option to crack hashes in background

##### Users where Kerberoasting is possible
####### Retrieve tickets -> output to file

# TODO same issue as above
# TODO change for dependance on auth method
print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Performing {bcolors.PURPLE}CME{bcolors.ENDC} kerberoasting (output hidden)")  
os.system(f"crackmapexec ldap {args.domain_controller_ip} -u {args.username} -p {args.password} --kerberoasting {save_dir}/users_kerberoasting.txt > /dev/null")
print("")
######## Option to crack hashes in background?

print("")
print(f"Files saved in {save_dir} as users_*.txt")

print("")
print(f"{bcolors.BOLD}Delegation Enumeration{bcolors.ENDC}")
print("=========================")
print("")


##### All objects with trusted for delegation -> output to file     					(userAccountControl:1.2.840.113556.1.4.803:=524288)
c.extend.standard.paged_search(search_base=default_search_base, search_filter='(userAccountControl:1.2.840.113556.1.4.803:=524288)', search_scope=ldap3.SUBTREE, attributes=["samaccountname"], generator=False)

with open(f"{save_dir}/full/objects_unconstrained_delegation_full.txt", "w") as f:
	f.write(str(c.response))
	
count = 0
with open(f"{save_dir}/delegation_unconstrained_objects.txt", "w") as f:
	for i in range(len(c.response)):
		if(c.response[i]["type"] == "searchResEntry"):
			f.write(str(c.response[i]["attributes"]["samaccountname"]) + "\n")
			count += 1

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found: {count} AD Objects with Unconstrained Delegations")


##### All objects with trusted for auth delegation -> output to file     					(userAccountControl:1.2.840.113556.1.4.803:=16777216)
c.extend.standard.paged_search(search_base=default_search_base, search_filter='(msDS-AllowedToDelegateTo=*)', search_scope=ldap3.SUBTREE, attributes=["useraccountcontrol","samaccountname","msDS-AllowedToDelegateTo"], generator=False)

with open(f"{save_dir}/full/objects_constrained_delegation_full.txt", "w") as f:
	f.write(str(c.response))
	
countC = 0
countCPT = 0
with open(f"{save_dir}/delegation_constrained_objects.txt", "w") as f1:
	with open(f"{save_dir}/delegation_constrained_w_protocol_transition_objects.txt", "w") as f2:
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

print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found: {countC} AD Objects with Constrained Delegations")
print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found: {countCPT} AD Objects with Constrained Delegations with Protocol Transition")


c.extend.standard.paged_search(search_base=default_search_base, search_filter='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)', search_scope=ldap3.SUBTREE, attributes=["samaccountname","msDS-AllowedToActOnBehalfOfOtherIdentity"], generator=False)

with open(f"{save_dir}/full/objects_rbcd_delegation_full.txt", "w") as f:
	f.write(str(c.response))
	
count = 0
with open(f"{save_dir}/delegation_rbcd_objects.txt", "w") as f:
	for i in range(len(c.response)):
		if(c.response[i]["type"] == "searchResEntry"):
			name = str(c.response[i]["attributes"]["samaccountname"])

			sF = '(|'
			sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(c.response[i]["attribute"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]))
			for ace in sd['Dacl'].aces:
				sF = sF + "(objectSid="+ace['Ace']['Sid'].formatCanonical()+")"
			sF = sF + ')'

			c.extend.standard.paged_search(search_base=default_search_base, search_filter=sF, search_scope=ldap3.BASE, attributes="*")

			for dele in c.response:
				f.write(f"{name} ::: delegates ::: {dele['attributes']['sAMAccountName']}\n")
				count += 1


c.extend.standard.paged_search(search_base=default_search_base, search_filter='(ms-DS-MachineAccountQuota=*)', search_scope=ldap3.SUBTREE, attributes=["ms-DS-MachineAccountQuota"], generator=False)


print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} Found: {count} AD Objects with Resource Based Constrained Delegations")

for resp in c.response:
	if(resp['type'] == "searchResEntry"):
		macctq = resp['attributes']['ms-DS-MachineAccountQuota']
		break

if(macctq <= 0):
	print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Machine Account Quota: {bcolors.OKGREEN}{macctq}{bcolors.ENDC}")
else:
	print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} Machine Account Quota: {bcolors.FAIL}{macctq}{bcolors.ENDC}")


print("")
print(f"Files saved in {save_dir} as delegation_*.txt")

print("")

