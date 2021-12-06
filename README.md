# Attack-Surface-Discovery

A POC script that leverages recon-NG and NMAP to perform automated attack surface discovery based on a given domain name. Results can be output in CSV, Excel, or JSON format. 

## Requirements

In order to run this code the following requirements should be met:

* Recommended operating system: Kali linux
* Copy of recon-ng installed
* Copy of recon-cli installed (recon-ng CLI)
* Copy of NMAP for active scanning
* Python 3.x

## Installation

1. Clone the Repo:
```
git clone https://github.com/GO0dspeed/Attack-Surface-Discovery.git
```

## Recon-ng modules required

recon.py will look for the following recon-ng modules in order to run properly. Recon.py will attempt to install any modules not currently installed but it's best to install them prior to running recon.py:

1. import/nmap
2. recon/domains-hosts/hackertarget
3. recon/domains-hosts/google_site_web"
4. recon/domains-hosts/shodan_hostname
5. recon/hosts-hosts/resolve
6. recon/hosts-ports/shodan_ip
7. recon/netblocks-hosts/shodan_net
8. reporting/csv
9. reporting/json
10. reporting/xlsx

## Usage

```
usage: recon.py [-h] -o {csv,excel,json} -w WORKSPACE -f FILENAME domain
```
