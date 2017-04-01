from argparse import RawTextHelpFormatter
import sys, time, os
import re
import argparse
import argcomplete

timestr = time.strftime("%Y%m%d-%H%M")


class colors:
    white = "\033[1;37m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    blue = "\033[1;34m"
    green = "\033[1;32m"
    lightblue = "\033[0;34m"


banner = colors.green + r"""
 ____  ____  ____  ____  ____  _________  ____  ____  ____  _________ 
||B ||||r ||||u ||||t ||||e ||||       ||||M ||||a ||||p ||||       ||
||__||||__||||__||||__||||__||||_______||||__||||__||||__||||_______||
|/__\||/__\||/__\||/__\||/__\||/_______\||/__\||/__\||/__\||/_______\|


"""+'\n' \
+ '\n brutemap.py v0.01' \
+ '\n Created by: Jacob Robles/@shellfail && Shane Young/@x90skysn3k' + '\n' + colors.normal + '\n'


#def get_ip_and_port():
#    with open(args.file, 'r') as nmap_file:
#        for line in nmap_file:
#            ip = None
#            try:
#                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)[0]
#            except:
#                pass 
#            openports = re.findall( '(\d+)\/open', line)
#            ports = []
#            ports += openports 
#            if ip and ports:
#                outputlist = [ip, ports]
#                return outputlist
#                print outputlist

def ip_by_port(port):
    with open(args.file, 'r') as nmap_file:
        iplist = []
        for line in nmap_file:
            if ' '+str(port)+'/open' in line:
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
                iplist += ip
    return iplist


def brute_ssh():                    
    port = 22
    outputlist = ip_by_port(port)
    print outputlist
                

def parse_args():
    
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=\

    banner + 
    "Usage: python brutemap.py <OPTIONS> \n")

    menu_group = parser.add_argument_group(colors.lightblue + 'Menu Options' + colors.normal)
    
    menu_group.add_argument('-f', '--file', help="Gnmap file to parse", required=True)
    
    argcomplete.autocomplete(parser)    
   
    args = parser.parse_args()

    output = None

    return args,output


if __name__ == "__main__":
    print(banner)
    args,output = parse_args()
    
    if args.file:
        brute_ssh()    
   

