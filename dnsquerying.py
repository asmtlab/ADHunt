
from ldap3 import *
from dns_structures import *


dc_ip = "10.129.204.226"
username = "htb-student"
password = "HTBRocks!"

s = Server(dc_ip, get_info=ALL)

#auth method
c = Connection(s, f"{dc_ip}\\{username}", password, authentication="NTLM")

#error check
c.bind()

domainroot = s.info.other['defaultNamingContext'][0]
forestroot = s.info.other['rootDomainNamingContext'][0]

zones = set()

c.search(search_base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'])

for entry in c.response:
    if entry['type'] != 'searchResEntry':
        continue

    zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}")


c.search(search_base=f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'])

for entry in c.response:
    if entry['type'] != 'searchResEntry':
        continue

    zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}")

c.search(search_base=f"CN=MicrosoftDNS,CN=System,{domainroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'])

for entry in c.response:
    if entry['type'] != 'searchResEntry':
        continue

    zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,CN=System,{domainroot}")


for zone in zones:
    print(zone)
    print("")
    c.extend.standard.paged_search(f'{zone}', "(objectClass=*)", search_scope=LEVEL, attributes=['dnsRecord','dNSTombstoned','name'], paged_size=500, generator=False)
    
    for entry in c.response:
        if entry['type'] != 'searchResEntry':
            print(entry)
            continue
       
        for record in entry["raw_attributes"]["dnsRecord"]:
            dr = DNS_RECORD(record)

            queryType = RECORD_TYPE_MAPPING[dr['Type']]
            recordname = entry["attributes"]["name"]
            
            # spent too many hours looking at this already https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ac793981-1c60-43b8-be59-cdbb5c4ecb8a
            if queryType == 'ZERO':
                data = DNS_RPC_RECORD_TS(dr["Data"])
                print({'name': recordname, 'type': queryType, 'value': data.dump()})
            elif queryType == 'A':
                data = DNS_RPC_RECORD_A(dr["Data"])
                print({'name':recordname, 'type': queryType, 'value': data.formatCanonical()})
            elif queryType in ['NS', 'PTR', 'CNAME']:
                data = DNS_RPC_RECORD_NODE_NAME(dr["Data"])
                print({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[0]].toFqdn()})
            elif queryType == 'TXT':
                data = DNS_RPC_RECORD_STRING(dr["Data"])
                print({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[0]]})                
            elif queryType == 'SRV':
                data = DNS_RPC_RECORD_SRV(dr["Data"])
                print({'name':recordname, 'type': queryType, 'value': data[list(data.fields)[3]].toFqdn()})
            elif queryType == 'AAAA':
                data = DNS_RPC_RECORD_AAAA(dr["Data"])
                print({'name':recordname, 'type': queryType, 'value': data.formatCanonical()})
            else:
                print("=======UNKNOWN DNS RECORD=======")
                print(f'name: {recordname}, type: {queryType}')
                print(dr.dump())
                print("================================")
            

