import ipaddress

def checkScope(ipt: str, scopeExclude: list, scopeInclude: list):
		new_ip = ipaddress.ip_address(ipt)
		for ipn in scopeExclude:
			if(new_ip in ipn):
				return False

		for ipn in scopeInclude:
			if(new_ip in ipn):
				return True
				
		return False

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