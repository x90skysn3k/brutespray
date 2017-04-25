# BruteSpray
Created by: Shane Young/@x90skysn3k && Jacob Robles/@shellfail 

# Description
BruteSpray takes nmap GNMAP output and automatically brute-forces services with default credentials using Medusa. 

# Usage
First do an nmap scan with '-oA nmap.gnmap'.

Command: python brutespray.py -h

Example: python brutespray.py --file nmap.gnmap --services all --threads 3 --hosts 5

# Status
Alpha v0.2

# Supported Services

* ssh
* ftp
* telnet
* vnc
* mssql
* mysql
* postgresql
* rsh
* imap
* nntp
* pcanywhere
* pop3
* rdp
* rexec
* rlogin
* smbnt
* smtp
* snmp
* svn
* vmauthd


