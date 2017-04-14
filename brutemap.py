from argparse import RawTextHelpFormatter
import sys, time, os
import subprocess
import re
import argparse
import argcomplete
from multiprocessing import Process


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
+ '\n brutemap.py v0.02' \
+ '\n Created by: Jacob Robles/@shellfail && Shane Young/@x90skysn3k' + '\n' + colors.normal + '\n'



def ip_by_port(port):
    with open(args.file, 'r') as nmap_file:
        iplist = []
        for line in nmap_file:
            if ' '+str(port)+'/open' in line:
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
                iplist += ip
    return iplist


def brute_ssh():                    
    if not args.port:
        port = "22"
    else:
        port = args.port
    tmp = "tmp/tmpssh"
    with open(tmp, 'w+') as f:
        outputlist = ip_by_port(port)
        f.write('\n'.join(outputlist))
        f.write('\n')
    
    
    subprocess.call(['medusa', '-H', tmp, '-U', 'wordlist/ssh/user', '-P', 'wordlist/ssh/password', '-M', 'ssh', '-t', args.threads, '-n', port, '-T', args.hosts])
    
    os.remove(tmp)

def brute_ftp():
    if not args.port:
        port = "21"
    else:
        port = args.port

    tmp = "tmp/tmpftp"
    with open(tmp, 'w+') as f:
        outputlist = ip_by_port(port)
        f.write('\n'.join(outputlist))
        f.write('\n')
        
    subprocess.call(['medusa', '-H', tmp, '-U', 'wordlist/ftp/user', '-P', 'wordlist/ftp/password', '-M', 'ftp', '-t', args.threads, '-n', port, '-T', args.hosts])
        
    os.remove(tmp)

def brute_telnet():
    if not args.port:
        port = "23"
    else:
        port = args.port

    tmp = "tmp/tmptel"
    with open(tmp, 'w+') as f:
        outputlist = ip_by_port(port)
        f.write('\n'.join(outputlist))
        f.write('\n')
        
    subprocess.call(['medusa', '-H', tmp, '-U', 'wordlist/telnet/user', '-P', 'wordlist/telnet/password', '-M', 'telnet', '-t', args.threads, '-n', port, '-T' , args.hosts])

    os.remove(tmp)

def brute_vnc():
    if not args.port:
        port = "5900"
    else:
        port = args.port

    tmp = "tmp/tmpvnc"
    with open(tmp, 'w+') as f:
        outputlist = ip_by_port(port)
        f.write('\n'.join(outputlist))
        f.write('\n')
        
    subprocess.call(['medusa', '-H', tmp, '-U', 'wordlist/vnc/user', '-P', 'wordlist/vnc/password', '-M', 'vnc', '-t', args.threads, '-n', port, '-T' , args.hosts])

    os.remove(tmp)

def brute_mssql():
    if not args.port:
        port = "1433"
    else:
        port = args.port

    tmp = "tmp/tmpmssql"
    with open(tmp, 'w+') as f:
        outputlist = ip_by_port(port)
        f.write('\n'.join(outputlist))
        f.write('\n')
        
    subprocess.call(['medusa', '-H', tmp, '-U', 'wordlist/mssql/user', '-P', 'wordlist/mssql/password', '-M', 'mssql', '-t', args.threads, '-n', port, '-T' , args.hosts])

    os.remove(tmp)

def brute_mysql():
    if not args.port:
        port = "3306"
    else:
        port = args.port

    tmp = "tmp/tmpmysql"
    with open(tmp, 'w+') as f:
        outputlist = ip_by_port(port)
        f.write('\n'.join(outputlist))
        f.write('\n')
        
    subprocess.call(['medusa', '-H', tmp, '-U', 'wordlist/mysql/user', '-P', 'wordlist/mysql/password', '-M', 'mysql', '-t', args.threads, '-n', port, '-T' , args.hosts])

    os.remove(tmp)

def parse_args():
    
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=\
 
    "Usage: python brutemap.py <OPTIONS> \n")

    menu_group = parser.add_argument_group(colors.lightblue + 'Menu Options' + colors.normal)
    
    menu_group.add_argument('-f', '--file', help="Gnmap file to parse", required=True)
    
    menu_group.add_argument('-s', '--service', help="specify service to attack", default="all")

    menu_group.add_argument('-t', '--threads', help="number of medusa threads", default="2")
    
    menu_group.add_argument('-T', '--hosts', help="number of hosts to test concurrently", default="1")    

    menu_group.add_argument('-p', '--port', help="specify custom port for service to try") 

    argcomplete.autocomplete(parser)    
   
    args = parser.parse_args()

    if args.port and args.service == "all":
        parser.error("--port requires --service to be specified")    
    
    output = None

    return args,output


if __name__ == "__main__":
    print(banner)
    args,output = parse_args()
    if not os.path.exists("tmp/"):
        os.mkdir("tmp/")
    tmppath = "tmp/"
    filelist = os.listdir(tmppath)
    for filename in filelist:
        os.remove(tmppath+filename)
   

 
    p_ssh = Process(target = brute_ssh)
    p_ftp = Process(target = brute_ftp)
    p_telnet = Process(target = brute_telnet)
    p_vnc = Process(target = brute_vnc)
    p_mssql = Process (target = brute_mssql)
    p_mysql = Process (target = brute_mysql)
    
    if args.service == 'ssh':
        brute_ssh()    
    elif args.service == 'ftp':
        brute_ftp() 
    elif args.service == 'telnet':
        brute_telnet()
    elif args.service == 'vnc':
        brute_vnc()
    elif args.service == 'mssql':
        brute_mssql()
    elif args.service == 'mysql':
        brute_mysql()
    elif args.service == 'all':
        p_ssh.start()
        p_ftp.start()
        p_telnet.start()
        p_vnc.start()
        p_mssql.start()
        p_mysql.start()


