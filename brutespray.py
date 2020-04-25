#! /usr/bin/python3
# -*- coding: utf-8 -*-
from argparse import RawTextHelpFormatter
import readline, glob
import sys, time, os
import subprocess
import xml.etree.ElementTree as ET
import re
import argparse
import threading
import itertools
import tempfile
import shutil
import json
from multiprocessing import Process

services = {}
loading = False

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
+ '\n brutespray.py v1.6.8' \
+ '\n Created by: Shane Young/@x90skysn3k && Jacob Robles/@shellfail' \
+ '\n Inspired by: Leon Johnson/@sho-luv' \
+ '\n Credit to Medusa: JoMo-Kun / Foofus Networks <jmk@foofus.net>\n' + colors.normal
#ascii art by: Cara Pearson

quiet_banner = colors.red + '~ BruteSpray ~' + colors.normal

class tabCompleter(object):

    def pathCompleter(self,text,state):
        line   = readline.get_line_buffer().split()

        return [x for x in glob.glob(text+'*')][state]

def interactive():
    t = tabCompleter()
    singluser = ""
    if args.interactive is True:
        print(colors.white + "\n\nWelcome to interactive mode!\n\n" + colors.normal)
        print(colors.red + "WARNING:" + colors.white + " Leaving an option blank will leave it empty and refer to default\n\n" + colors.normal)
        print("Available services to brute-force:")
        for serv in services:
            srv = serv
            for prt in services[serv]:
                iplist = services[serv][prt]
                port = prt
                plist = len(iplist)
                print("Service: " + colors.green + str(serv) + colors.normal + " on port " + colors.red + str(port) + colors.normal + " with " + colors.red + str(plist) + colors.normal + " hosts")

        args.service = input('\n' + colors.lightblue + 'Enter services you want to brute - default all (ssh,ftp,etc): ' + colors.red)

        args.threads = input(colors.lightblue + 'Enter the number of parallel threads (default is 2): ' + colors.red)

        args.hosts = input(colors.lightblue + 'Enter the number of parallel hosts to scan per service (default is 1): ' + colors.red)

        if args.passlist is None or args.userlist is None:
            customword = input(colors.lightblue + 'Would you like to specify a wordlist? (y/n): ' + colors.red)
        if customword == "y":
            readline.set_completer_delims('\t')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(t.pathCompleter)
            if args.userlist is None and args.username is None:
                args.userlist = input(colors.lightblue + 'Enter a userlist you would like to use: ' + colors.red)
                if args.userlist == "":
                    args.userlist = None
            if args.passlist is None and args.password is None:
                args.passlist = input(colors.lightblue + 'Enter a passlist you would like to use: ' + colors.red)
                if args.passlist == "":
                    args.passlist = None

        if args.username is None or args.password is None: 
            singluser = input(colors.lightblue + 'Would to specify a single username or password (y/n): ' + colors.red)
        if singluser == "y":
            if args.username is None and args.userlist is None:
                args.username = input(colors.lightblue + 'Enter a username: ' + colors.red)
                if args.username == "":
                    args.username = None
            if args.password is None and args.passlist is None:
                args.password = input(colors.lightblue + 'Enter a password: ' + colors.red)
                if args.password == "":
                    args.password = None

        if args.service == "":
            args.service = "all"
        if args.threads == "":
            args.threads = "2"
        if args.hosts == "":
            args.hosts = "1"

    print(colors.normal)

NAME_MAP = {"ms-sql-s": "mssql",
            "microsoft-ds": "smbnt",
            "pcanywheredata": "pcanywhere",
            "postgresql": "postgres",
            "shell": "rsh",
            "exec": "rexec",
            "login": "rlogin",
            "smtps": "smtp",
            "submission": "smtp",
            "imaps": "imap",
            "pop3s": "pop3",
            "iss-realsecure": "vmauthd",
            "snmptrap": "snmp"}

def make_dic_gnmap():
    global loading
    global services

    supported = ['ssh','ftp','postgres','telnet','mysql','ms-sql-s','shell',
                 'vnc','imap','imaps','nntp','pcanywheredata','pop3','pop3s',
                 'exec','login','microsoft-ds','smtp', 'smtps','submission',
                 'svn','iss-realsecure','snmptrap','snmp']


    port = None
    with open(args.file, 'r') as nmap_file:
        for line in nmap_file:
            for name in supported:
                matches = re.compile(r'([0-9][0-9]*)/open/[a-z][a-z]*//' + name)
                try:
                    port =  matches.findall(line)[0]
                except:
                    continue

                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
                tmp_ports = matches.findall(line)

                for tmp_port in tmp_ports:

                    name = NAME_MAP.get(name, name)

                    if name in services:
                        if tmp_port in services[name]:
                            services[name][tmp_port] += ip
                        else:
                            services[name][tmp_port] = ip
                    else:
                        services[name] = {tmp_port:ip}

    loading = True

def make_dic_xml():
    global loading
    global services
    supported = ['ssh','ftp','postgresql','telnet','mysql','ms-sql-s','rsh',
                 'vnc','imap','imaps','nntp','pcanywheredata','pop3','pop3s',
                 'exec','login','microsoft-ds','smtp','smtps','submission',
                 'svn','iss-realsecure','snmptrap','snmp']
    tree = ET.parse(args.file)
    root = tree.getroot()
    for host in root.iter('host'):
        ipaddr = host.find('address').attrib['addr']
        for port in host.iter('port'):
            cstate = port.find('state').attrib['state']
            if cstate == "open":
                try:
                    name = port.find('service').attrib['name']
                    tmp_port = port.attrib['portid']
                    iplist = ipaddr.split(',')
                except:
                    continue
                if name in supported:
                    name = NAME_MAP.get(name, name)
                    if name in services:
                        if tmp_port in services[name]:
                            services[name][tmp_port] += iplist
                        else:
                            services[name][tmp_port] = iplist
                    else:
                        services[name] = {tmp_port:iplist}

    loading = True

def make_dic_json():
    global loading
    global services

    supported = ['ssh','ftp','postgres','telnet','mysql','ms-sql-s','shell',
                 'vnc','imap','imaps','nntp','pcanywheredata','pop3','pop3s',
                 'exec','login','microsoft-ds','smtp', 'smtps','submission',
                 'svn','iss-realsecure','snmptrap','snmp']

    with open(args.file, "r") as jsonlines_file:
        for line in jsonlines_file:
            data = json.loads(line)
            try:
                host, port, name = data["host"], data["port"], data["service"]
                
                if name in supported:
                    name = NAME_MAP.get(name, name) 
                    if name not in services:
                        services[name] = {}
                    if port not in services[name]:
                        services[name][port] = []
                    if host not in services[name][port]:
                        services[name][port].append(host)
            except KeyError as e:
                sys.stderr.write("\n[!] Field: " + str(e) + "is missing")
                sys.stderr.write("\n[!] Please provide the json fields. ")               
                continue
    loading = True 

def brute(service,port,fname,output):
    if args.userlist is None and args.username is None:
        userlist = '/usr/share/brutespray/wordlist/'+service+'/user'
        if not os.path.exists(userlist):
            userlist = 'wordlist/'+service+'/user'
        uarg = '-U'
    elif args.userlist:
        userlist = args.userlist
        uarg = '-U'
    elif args.username:
        userlist = args.username
        uarg = '-u'

    if args.passlist is None and args.password is None:
        passlist = '/usr/share/brutespray/wordlist/'+service+'/password'
        if not os.path.exists(passlist):
            passlist = 'wordlist/'+service+'/password'
        parg = '-P'
    elif args.passlist:
        passlist = args.passlist
        parg = '-P'
    elif args.password:
        passlist = args.password
        parg = '-p'

    if args.continuous:
        cont = ''
    else:
        cont = '-F'
    if service == "smtp":
        aarg = "-m"
        auth = "AUTH:LOGIN"
    else:
        aarg = ''
        auth = ''

    p = subprocess.Popen(['medusa', '-b', '-H', fname, uarg, userlist, parg, passlist, '-M', service, '-t', args.threads, '-n', port, '-T', args.hosts, cont, aarg, auth], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=-1)

    out = "[" + colors.green + "+" + colors.normal + "] "
    output_file = output + '/' + port + '-' + service + '-success.txt'
    
 
    for line in iter(p.stdout.readline, b''):
        print(line.decode('utf-8').strip('\n'))
        sys.stdout.flush()
        time.sleep(0.0001)
        if 'SUCCESS' in line.decode('utf-8'):
            f = open(output_file, 'a')
            f.write(out + line.decode('utf-8'))
            f.close()

def animate():
    sys.stdout.write('\rStarting to brute, please make sure to use the right amount of ' + colors.green + 'threads(-t)' + colors.normal + ' and ' + colors.green + 'parallel hosts(-T)' + colors.normal + '...  \n')
    t_end = time.time() + 2
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if not time.time() < t_end:
            break
        sys.stdout.write('\rOutput will be written to the folder: ./' + colors.green + args.output + colors.normal + "/ "+ c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\n\nBrute-Forcing...     \n')
    time.sleep(1)

def loading():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if loading == True:
            break
        sys.stdout.write('\rLoading File: ' + c)
        sys.stdout.flush()
        time.sleep(0.01)

def getInput(filename):
    in_format = None
    with open(filename) as f:
        line = f.readlines()
        if filename.endswith("gnmap"):
            in_format = "gnmap"
        if filename.endswith("json"):
            in_format = "json"
        if filename.endswith("xml"):
            in_format = "xml"
        if '{' in line[0]:
            in_format = "json"
        if '# Nmap' in line[0] and not 'Nmap' in line[1]:
            in_format = "gnmap"
        if '<?xml ' in line[0]:
            in_format = "xml"
        if in_format is None:
            print('File is not correct format!\n')
            sys.exit(0)

    return in_format 

def parse_args():

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=\

    "Usage: python brutespray.py <OPTIONS> \n")

    menu_group = parser.add_argument_group(colors.lightblue + 'Menu Options' + colors.normal)

    #menu_group.add_argument('-f', '--file', help="GNMAP or XML file to parse", required=False, default=None)
    menu_group.add_argument('-f', '--file', help="GNMAP, JSON or XML file to parse", required=False, default=None)
    menu_group.add_argument('-o', '--output', help="Directory containing successful attempts", default="brutespray-output")
    menu_group.add_argument('-s', '--service', help="specify service to attack", default="all")
    menu_group.add_argument('-t', '--threads', help="number of medusa threads", default="2")
    menu_group.add_argument('-T', '--hosts', help="number of hosts to test concurrently", default="1")
    menu_group.add_argument('-U', '--userlist', help="reference a custom username file", default=None)
    menu_group.add_argument('-P', '--passlist', help="reference a custom password file", default=None)
    menu_group.add_argument('-u', '--username', help="specify a single username", default=None)
    menu_group.add_argument('-p', '--password', help="specify a single password", default=None)
    menu_group.add_argument('-c', '--continuous', help="keep brute-forcing after success", default=False, action='store_true')
    menu_group.add_argument('-i', '--interactive', help="interactive mode", default=False, action='store_true')    
    menu_group.add_argument('-m', '--modules', help="dump a list of available modules to brute", default=False, action='store_true')    
    menu_group.add_argument('-q', '--quiet', help="supress banner", default=False, action='store_true')   

    args = parser.parse_args()

    if args.file is None and args.modules is False:
        parser.error("argument -f/--file is required")
    return args

if __name__ == "__main__":
    args = parse_args()
    
    if args.quiet == False:
        print(banner)
    else:
        print(quiet_banner)

    supported = ['ssh','ftp','telnet','vnc','mssql','mysql','postgresql','rsh',
                'imap','nntp','pcanywhere','pop3',
                'rexec','rlogin','smbnt','smtp',
                'svn','vmauthd','snmp']
    #temporary directory for ip addresses

    if args.modules is True:
        print(colors.lightblue + "Supported Services:\n" + colors.green)
        print(('\n'.join(supported)))
        print(colors.normal + "\n") 
    try:
        tmppath = tempfile.mkdtemp(prefix="brutespray-tmp")
    except:
        sys.stderr.write("\nError while creating brutespray temp directory.")
        exit(4)

    if not os.path.exists(args.output):
        os.mkdir(args.output)

    if os.system("command -v medusa > /dev/null") != 0:
        sys.stderr.write("Command medusa not found. Please install medusa before using brutespray")
        exit(3)

    if args.file is None:
        sys.exit(0)

    if args.passlist and not os.path.isfile(args.passlist):
        sys.stderr.write("Passlist given does not exist. Please check your file or path\n")
        exit(3)

    if args.userlist and not os.path.isfile(args.userlist):
        sys.stderr.write("Userlist given does not exist. Please check your file or path\n")
        exit(3)

    if os.path.isfile(args.file):        
        try:
            t = threading.Thread(target=loading)
            t.start()
            in_format = getInput(args.file)
            {
                "gnmap": make_dic_gnmap,
                "xml":   make_dic_xml,
                "json":  make_dic_json
            }[in_format]()
        except:
            print("\nFormat failed!\n")
            loading = True
            sys.exit(0)

        if args.interactive is True:
            interactive()

        animate()

        if services == {}:
            print("\nNo brutable services found.\n Please check your Nmap file.")
    else:
        print("\nError loading file, please check your filename.")

    to_scan = args.service.split(',')
    for service in services:
        if service in to_scan or to_scan == ['all']:
            for port in services[service]:
                fname = tmppath + '/' +service + '-' + port
                iplist = services[service][port]
                f = open(fname, 'w+')
                for ip in iplist:
                    f.write(ip + '\n')
                f.close()
                brute_process = Process(target=brute, args=(service,port,fname,args.output))
                brute_process.start()

    #need to wait for all of the processes to run...
    #shutil.rmtree(tmppath, ignore_errors=False, onerror=None)
