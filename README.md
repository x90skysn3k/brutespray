# BruteSpray
Created by: Shane Young/@x90skysn3k && Jacob Robles/@shellfail 

Inspired by: Leon Johnson/@sho-luv

# Demo

https://youtu.be/C-CVLbSEe_g

# Description
BruteSpray takes nmap GNMAP output and automatically brute-forces services with default credentials using Medusa. BruteSpray can even find non-standard ports by using the -sV inside Nmap.  

# Usage
First do an nmap scan with '-oA nmap.gnmap'.

Command: python brutespray.py -h

Example: python brutespray.py --file nmap.gnmap --services all --threads 3 --hosts 5

# Version
v1.3

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
* rexec
* rlogin
* smbnt
* smtp
* snmp
* svn
* vmauthd

# Changelog
* v1.3
    * added the ability to stop on success
    * added the ability to reference custom userlists and passlists
    * added the ability to specify specific user & passwords
