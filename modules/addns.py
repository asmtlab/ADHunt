import ldap3
from ldap3 import *
from impacket.structure import Structure
import socket
from struct import unpack, pack
import datetime
from modules.clogging import Logging
import os
import json

# structs mostly stolen from adidnsdump, specifically: https://github.com/dirkjanm/adidnsdump/blob/65169b2b5c9dc2b51afe03851d42156085c4cd68/adidnsdump/dnsdump.py#L327

# https://en.wikipedia.org/wiki/List_of_DNS_record_types
RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    3: 'MD',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    18: 'AFSDB',
    19: 'X25',
    20: 'ISDN',
    21: 'RT',
    24: 'SIG',
    25: 'KEY',
    28: 'AAAA',
    30: 'NXT',
    33: 'SRV',
    34: 'ATMA',
    35: 'NAPTR',
    39: 'DNAME',
    43: 'DS',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    49: 'DHCID',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    52: 'TLSA',
    65281: 'WINS', # this may be a negative number its xFF01 (?)
    65281: 'WINSR', # ^^^
}


class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)

class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

class DNS_RPC_RECORD_STRING(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.6
    """
    structure = (
        ('stringData', ':', DNS_COUNT_NAME),
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )

    def formatCanonical(self):
        return socket.inet_ntop(socket.AF_INET6, self['ipv6Address'])

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = int(self['entombedTime'] / 10)
        try:
            return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)
        except OverflowError:
            return None


"""
This searches for DNS Records that are saved in Active directory.  It outputs all records to a 
file and returns A records and NS records. It outputs the amount of records found per zone to screen.

Num of LDAP queries: 3 + O(n)
Created files: 1

# TODO LIST
# - IPv6 records and scope checking support
# - stealthy mode to cut down noise -> check less zones
"""
class ADDNSEnumeration:
    def __init__(self, c: Connection, s: Server, save_dir: str, fresh: bool):
        self.s = s
        self.c = c
        self.save_dir = save_dir
        self.fresh = fresh
        

    def run(self):
        Logging.header("AD DNS Information")

        #if we are not mandated to run the module again than check if we can load from a save file TODO
        if(not self.fresh):
            if(os.path.isfile(f"{self.save_dir}/saves/addns.lod")):
                with open(f"{self.save_dir}/saves/addns.lod", "r") as f:
                    try:
                        Logging.info("Loading from save file")

                        out = json.load(f)

                        Logging.end()
                        
                        return out["NS"], out["A"]
                    except Exception as e:
                        print(e)

        domainroot = self.s.info.other['defaultNamingContext'][0]
        forestroot = self.s.info.other['rootDomainNamingContext'][0]

        zones = set()

        self.c.extend.standard.paged_search(search_base=f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'], generator=False)

        for entry in self.c.response:
            if entry['type'] != 'searchResEntry':
                continue

            zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}")

        self.c.extend.standard.paged_search(search_base=f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'], generator=False)

        for entry in self.c.response:
            if entry['type'] != 'searchResEntry':
                continue

            zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,DC=ForestDnsZones,{forestroot}")

        self.c.extend.standard.paged_search(search_base=f"CN=MicrosoftDNS,CN=System,{domainroot}" , search_filter='(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'], generator=False)

        for entry in self.c.response:
            if entry['type'] != 'searchResEntry':
                continue

            zones.add(f"DC={entry['attributes']['dc']},CN=MicrosoftDNS,CN=System,{domainroot}")

        # we need to save some records in memory for use in converting domain controllers to ips
        A_records = [] # IPv4 to DNS records
        NS_records = [] # namesever records

        with open(f"{self.save_dir}/ad_dns_dump.txt", "w") as f:
            for zone in zones:
                num_records = 0
                f.write(zone)
                f.write("\n\n")
                self.c.extend.standard.paged_search(f'{zone}', "(objectClass=*)", search_scope=LEVEL, attributes=['dnsRecord','dNSTombstoned','name'], paged_size=500, generator=False)
                
                for entry in self.c.response:
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
                
                Logging.info(f"Found zone: {zone}: with {num_records} records")			

        Logging.fileinfo(f"{self.save_dir}/ad_dns_dump.txt")

        with open(f"{self.save_dir}/saves/addns.lod", "w") as f:
            saveobj = {}
            saveobj["A"] = A_records
            saveobj["NS"] = NS_records
            f.write(json.dumps(saveobj))

        Logging.end()

        return NS_records, A_records
