# ADHunt v3.0
## Description
AD Hunt is a tool for enumerating Active Directory Enviroments looking for interesting AD objects, vulnerabilities, and misconfigurations. It currently uses a combination ldap queries and available tooling. It was built as a follow up to [LinWinPwn](https://github.com/lefayjey/linWinPwn).

It currently enumerates the enviroment looking for DNS information, AD information, and SMB information

## Use Cases

This tool is designed for when you have a known domain controller and user for that dc and need to quickly gather useful information.  It only works from a linux system.

## Getting Started
The AD Hunt tool is relatively intuitive.
```
usage: python3 adhunt.py [-h] [-i] [--dc-ip DOMAIN_CONTROLLER_IP] [-u USERNAME] [-p PASSWORD] [-H HASH] [-d DOMAIN] [-s SCOPE]
                         [--detection-mode {passive,aggressive,moderate,stealthy}] [-q] [--no-scan] [--no-banner] [--ssl]
                         [--just {pass-pols,delegations,users,certificates,ad-dns,nameservers,domain-controllers,systems,system-vulns,smb} [{pass-pols,delegations,users,certificates,ad-dns,nameservers,domain-controllers,systems,system-vulns,smb} ...]]

Active Directory Enumeration Tool

Example usage:

$ python3 adhunt.py --install
$ python3 adhunt.py --dc-ip 10.129.150.235 -u grace -p Inlanefreight01! --scope i:10.129.0.0/16,e:10.129.10.10 --no-scan --quiet
$ python3 adhunt.py --dc-ip 10.129.23.200 -u user -H "5B0391923089960876FDE78389BE2CE2:F1223169E60A2513B6D8C93AE3A77B49" --scope i:10.129.0.100

options:
  -h, --help            show this help message and exit
  -i, --install         install nessecary components
  --dc-ip DOMAIN_CONTROLLER_IP
                        The IP of the domain controller targeted for enumeration
  -u USERNAME, --username USERNAME
                        The username of the user for enumation purposes
  -p PASSWORD, --password PASSWORD
                        The password of the supplied user
  -H HASH, --hash HASH  The hash for pass the hash authentication format [LM:]NTLM
  -d DOMAIN, --domain DOMAIN
                        The domain of the given user, if not provided fetched automatically from LDAP service name
  -s SCOPE, --scope SCOPE
                        The scope of valid ips for checking ranges when performing vulnerability scanning and enumeration. Include ranges with
                        i, and exclude with e. Seperate args by commas, For example a valid scope would be --scope
                        i:10.129.0.0/24,e:10.129.0.129
  --detection-mode {passive,aggressive,moderate,stealthy}
                        passive [default] (only scan ips found from ad dns information), moderate (scan ips from ad dns and perform regular dns
                        enumeration), aggressive (scan everything in scope), stealthy (TODO)
  -q, --quiet           Don't display output from tools
  --no-scan             Do not scan found ips for vulnerabilities
  --no-banner           Do not display the banner
  --ssl                 Should connections be made with ssl
  --just {pass-pols,delegations,users,certificates,ad-dns,nameservers,domain-controllers,systems,system-vulns,smb} [{pass-pols,delegations,users,certificates,ad-dns,nameservers,domain-controllers,systems,system-vulns,smb} ...]
                        only run the specified check(s) and its required other checks
```

First things first, run the install command to ensure all the necessary dependancies are taken care of.

```
python3 adhunt.py -i
```

Now that all of the necessary dependancies are installed if we had already cracked the user account "adam:P4ssW0rd" we could run the tool as follows and enumerate information.

```
python3 -i adhunt.py -u adam -p P4ssW0rd -d example.com --dc-ip 10.129.133.45
```

### How it works
The script is broken down into modules.  These modules provide the actual enumeration and run all the tests.  The current active modules are pass-pols,delegations,users,certificates,ad-dns,nameservers,domain-controllers,systems,system-vulns,smb.  You can learn more about them by checking out the source code.  By default all modules are run, however in the case where you might just want to run a specific module, you can do that too. Be aware though that some modules are dependant on other modules. In order for them to run those modules must run too and will run even when not specified.  

### Author
[Charlie Fligg](https://github.com/FL1GG) - Charlie.Fligg@cisa.dhs.gov
