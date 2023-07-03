#!/usr/bin/python3

import hashlib
from termcolor import colored
from urllib.request import urlopen
import pyfiglet as pf

print (pf.figlet_format("Venus-Hegel", justify="center"))

enterhash = input("[*] Paste sha256 Value: ")

secretlist = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt').read(), 'utf-8')

for secret in secretlist.split('\n'):
    hegelguess = hashlib.sha256(bytes(secret, 'utf-8')).hexdigest()
    if hegelguess == enterhash:
        print(colored("[*] Hegel Revealed: " + str(secret), 'blue'))
        quit()
    else:
        print(colored("[*] Hegel Cannot Reveal " + str(secret) + " no match", 'red'))
        
print("Try Other Lists")
       
