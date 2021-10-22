# BruteSpray
![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg)
![Version](https://img.shields.io/badge/Version-1.8-red)


Created by: Shane Young/@t1d3nio && Jacob Robles/@shellfail 

Inspired by: Leon Johnson/@sho-luv

Credit to Medusa: JoMo-Kun / Foofus Networks - http://www.foofus.net

# Demo

https://youtu.be/C-CVLbSEe_g

# Description
BruteSpray takes Nmap GNMAP/XML output, newline separated JSON, Nexpose `XML Export` output or Nessus `.nessus` exports and automatically brute-forces services with default credentials using Medusa. BruteSpray finds non-standard ports, make sure to use `-sV` with Nmap.

<img src="http://i.imgur.com/k9BDB5R.png" width="500">

# Installation

```pip install -r requirements.txt```

On Kali:

```apt-get install brutespray```

# Usage
If using Nmap, scan with ```-oG nmap.gnmap``` or ```-oX nmap.xml```.

If using Nexpose, export the template `XML Export`. 

If using Nessus, export your `.nessus` file.

Command: ```python brutespray.py -h```

Command: ```python brutespray.py --file nmap.gnmap```

Command: ```python brutesrpay.py --file nmap.xml```

Command: ```python brutespray.py --file nmap.xml -i```

<img src="https://i.imgur.com/PgXEw36.png" width="450">

## Examples

#### Using Custom Wordlists:

```python brutespray.py --file nmap.gnmap -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt --threads 5 --hosts 5```

#### Brute-Forcing Specific Services:

```python brutespray.py --file nmap.gnmap --service ftp,ssh,telnet --threads 5 --hosts 5```

#### Specific Credentials:
   
```python brutespray.py --file nmap.gnmap -u admin -p password --threads 5 --hosts 5```

#### Continue After Success:

```python brutespray.py --file nmap.gnmap --threads 5 --hosts 5 -c```

#### Use Nmap XML Output

```python brutespray.py --file nmap.xml --threads 5 --hosts 5```

#### Use JSON Output

```python brutespray.py --file out.json --threads 5 --hosts 5```

#### Interactive Mode

```python brutespray.py --file nmap.xml -i```

<img src="https://i.imgur.com/zBXEU33.png" width="600">

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
* svn
* vmauthd
* snmp

# Data Specs
```json
{"host":"127.0.0.1","port":"3306","service":"mysql"}
{"host":"127.0.0.10","port":"3306","service":"mysql"}
...
```
If using Nexpose, export the template `XML Export`. 

If using Nessus, export your `.nessus` file.

# Combo Option
When you specify a combo option `-C`, it will read the specified file and attempt the host:user:pass on each discovered service from Nmap. If you just want to specify only a username and password leave the host blank as shown below.
```
:user:pass
:user1:pass1
```
or
```
127.0.0.1:user:pass
127.0.0.10:user1:pass1
```

# Changelog
Changelog notes are available at [CHANGELOG.md](https://github.com/x90skysn3k/brutespray/blob/master/CHANGELOG.md)
