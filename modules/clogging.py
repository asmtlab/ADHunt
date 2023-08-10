from modules.common import *

class Logging:
	
    @staticmethod
    def header(text: str):
        print("")
        print(f"{bcolors.BOLD}{text}{bcolors.ENDC}")
        print("=========================")
        print("")

    @staticmethod
    def info(text: str):
        print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} {text}")

    @staticmethod
    def question(text: str):
        print(f"{bcolors.INSTALL}[?]{bcolors.ENDC} {text}")

    @staticmethod
    def exclaim(text: str):
        print(f"{bcolors.INSTALL}[!]{bcolors.ENDC} {text}")

    @staticmethod
    def star(text: str):
        print(f"{bcolors.INSTALL}[*]{bcolors.ENDC} {text}")

    @staticmethod
    def infov(text: str, value: str):
        print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} {text}: {value}")

    @staticmethod
    def fileinfo(text:str):
        print("")
        print(f"Files saved to {text}")

    @staticmethod
    def end():
        print("")
    
    @staticmethod
    def fail(text:str, value:str):
        print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} {text}: {bcolors.FAIL}{value}{bcolors.ENDC}")
    
    @staticmethod
    def ok(text:str, value:str):
        print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} {text}: {bcolors.OKGREEN}{value}{bcolors.ENDC}")

    @staticmethod
    def tool(text:str, value:str):
        print(f"{bcolors.INSTALL}[+]{bcolors.ENDC} {bcolors.PURPLE}{text}{bcolors.ENDC}: {value}")
