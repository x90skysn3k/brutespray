# BruteMap
Created by: Jacob Robles/@shellfail && Shane Young/@x90skysn3k

# Description
BruteMap takes nmap GNMAP output and automatically brute-forces services with default credentials using Medusa. 

# Usage
First do an nmap scan with '-oA nmap.gnmap'.

Command: python brutemap.py -h

Example: python brutemap.py --file nmap.gnmap --services all --threads 3
