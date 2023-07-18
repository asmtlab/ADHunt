# ADHunt v2.0
## Description
AD Hunt is a tool for enumerating Active Directory Enviroments looking for interesting AD objects, vulnerabilities, and misconfigurations. It currently uses a combination ldap queries and available tooling. It was built as a follow up to [LinWinPwn](https://github.com/lefayjey/linWinPwn).

## Use Cases

This tool is designed for when you have a known domain controller and user for that dc and need to quickly gather useful information.  It currently only works from a linux system.

## Getting Started
The AD Hunt tool is relatively intuitive.
```
usage: python3 adhunt.py [-h] [-i] [--dc-ip DOMAIN_CONTROLLER_IP] [-u USERNAME] [-p PASSWORD] [-d DOMAIN]

Active Directory Enumeration tool

options:
  -h, --help            show this help message and exit
  -i, --install         install nessecary components
  --dc-ip DOMAIN_CONTROLLER_IP
                        The IP of the domain controller targeted for enumeration
  -u USERNAME, --username USERNAME
                        The username of the user for enumation purposes
  -p PASSWORD, --password PASSWORD
                        The password of the supplied user
  -d DOMAIN, --domain DOMAIN
                        The domain of the given user
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
The script is broken down into sections. The sections are "Target Information","Password Policies","AD DNS Enumeration", "NameServer Enumeration", "Domain Controller Scanning", "System Scanning", "Certificate Services", "User Enumeration", "Delegation Enumeration"

In regards to scanning for systems and Domain controllers, the script is looking at the DNS information stored in Active directory. Since this is an AD tool there is no need to do full ip ranges scans.
