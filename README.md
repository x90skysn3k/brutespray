# BruteMap
Created by: Shane Young/@x90skysn3k && Jacob Robles/@shellfail 

# Description
BruteMap takes nmap GNMAP output and automatically brute-forces services with default credentials using Medusa. 

# Usage
First do an nmap scan with '-oA nmap.gnmap'.

Command: python brutemap.py -h

Example: python brutemap.py --file nmap.gnmap --services all --threads 3 --hosts 5

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

# Coming Soon

* imap
* nntp
* pcanywhere
* pop3
* rdp
* rexec
* rlogin
* rsh
* smbnt
* smtp
* snmp
* svn
* vmauthd


