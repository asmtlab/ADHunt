# ADHunt v2.0
## Description
AD Hunt is a tool for enumerating Active Directory Enviroments looking for interesting AD objects, vulnerabilities, and misconfigurations. It currently uses a combination ldap queries and available tooling. It was built as a follow up to [LinWinPwn](https://github.com/lefayjey/linWinPwn).

## Use Cases

This tool is designed for when you have a known domain controller and user for that dc and need to quickly gather useful information.  It currently only works from a linux system.

## Getting Started
The AD Hunt tool is relatively intuitive.
```
python3 adhunt.py --help
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
