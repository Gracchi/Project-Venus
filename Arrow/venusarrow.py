#!/usr/bin/python3
#Venus Project - Arrow

from socket import *
import argparse
import optparse
from threading import *
import pyfiglet as pf
from termcolor import colored 

print (pf.figlet_format("Venus-Arrow", justify="center"))

def connScan(tgtHost, tgtPort):
    try:
        sock = socket(AF_INET,  SOCK_STREAM)
        sock.connect((tgtHost, tgtPort))
        print (colored('[+] %d/tcp Open' % tgtPort, 'green'))
    except:
        print (colored('[-] %d/tcp Closed' % tgtPort, 'red'))
        
    finally:
        sock.close()       

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)       
    except:
        print ('Cannot Resolve Host %s ' %tgtHost)
    try:
        tgtName = gethostbyaddr(tgtIP)
        print('[+] Scan result for : ' + tgtName[0])
    except:
        print('[+] Scan result for : ' + tgtIP)
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()    
def main():
    parser = optparse.OptionParser('Usage of program: ' + '-H <target host> -p <target port>')
    parser.add_option('-H', dest= 'tgtHost' , type= 'string' , help= 'specific target host')
    parser.add_option('-P', dest= 'tgtPort' , type= 'string' , help= 'specific target port seperated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts)
        
if __name__== "__main__":
    main()

