# ipam-lite

Simple IPAM reporting tool

## Purpose

This is a very simple IPAM (IP Address Management) reporting tool, which looks
at DNS, DHCP and Arpwatch data. It produces a report of IP -> DHCP mappings,
and includes info from arpwatch on when the MAC was last seen.

Some basic mismatch and parsing errors are reported.

It is mainly a reporting tool for when DNS and DHCP information has diverged
over time, and for giving an overall IP/DNS report for a given subnet.

It is assumed that the DHCP entries are fixed-address hosts; i.e. clients pick
up addresses via DHCP, but the entries are fixed and not from a pool.

It does not:

* operate a full IPAM system, with a managed database populating DNS and DHCP
* perform any editing or fixing of issues

## Report

It highlights some basic errors which might creep into a non-IPAM-managed setup:

* mismatch between IP -> hostname -> IP mappings (incorrect forward/reverse RRs
  in DNS)
* malformed MAC address in DHCP
* hostnames in DHCP which don't resolve

It can also print a compressed report of unassigned IP addresses in the range.

## Usage

    $ ./ipam-lite.py -h
    usage: ipam-lite.py [-h] [-v] [-d] [-e] [-u] netaddress netmask domain arp_file dhcp_file

    positional arguments:
      netaddress            IPv4 network address
      netmask               IPv4 network mask, in CIDR 'slash' notation
      domain                default DNS domain name for hosts
      arp_file              the arp.dat file from arpwatch (typically
                            /var/lib/arpwatch/arp.dat)
      dhcp_file             the dhcpd.conf file (typically /etc/dhcpd/dhcpd.conf)
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         increase output verbosity
      -d, --dhcp_hostnames  check for hostnames in DHCP which don't resolve
      -e, --errors          display parsing and resolution errors
      -u, --unassigned      only display lists of unassigned/free IP addresses

## Examples

    $ ./ipam-lite.py 10.20.112.0 22 my.dns.domain arp/arp.dat dhcp/dhcpd.conf
    IPAM-Lite Report for 10.20.112.0/22
    IP               | Host                     | Host->IP | MAC (DHCP)         | MAC (ARP)          | Last seen (ARP)      
    ---------------- | ------------------------ | -------- | ------------------ | ------------------ | ---------------------
    10.20.112.1      | router01                 | OK       | -                  | 55:55:55:55:55:38  | 2016-08-18 [42 days] 
    10.20.112.2      | server01                 | OK       | 55:55:55:55:55:5f  | 55:55:55:55:55:37  | 2016-08-18 [42 days] 
    10.20.112.3      | server02                 | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:38  | 2016-08-18 [42 days] 
    10.20.112.4      | server03                 | OK       | -                  | -                  | -                    
    10.20.112.5      | server04                 | OK       | -                  | -                  | -                    
    10.20.112.6      | server05                 | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:bf  | 2016-08-18 [42 days] 
    10.20.112.7      | server06                 | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:2f  | 2016-08-18 [42 days] 
    10.20.112.8      | server07                 | OK       | -                  | 55:55:55:55:55:cc  | 2016-08-18 [42 days] 
    10.20.112.9      | server08                 | OK       | -                  | 55:55:55:55:55:90  | 2016-08-18 [42 days] 
    10.20.112.10     | server09                 | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:3a  | 2016-08-18 [42 days] 
    10.20.112.11     | -                        | -        | -                  | -                  | -                    
    10.20.112.12     | node001                  | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:90  | 2016-08-18 [42 days] 
    10.20.112.13     | node002                  | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:cc  | 2016-08-18 [42 days] 
    10.20.112.14     | node003                  | OK       | 55:55:55:55:55:5c  | -                  | -                    
    10.20.112.15     | node004                  | OK       | -                  | 55:55:55:55:55:f2  | 2016-08-18 [42 days] 
    10.20.112.16     | node005                  | OK       | 55:55:55:55:55:3c  | -                  | -                    
    10.20.112.17     | node006                  | OK       | -                  | -                  | -                    
    10.20.112.18     | node007                  | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:08  | 2016-08-18 [42 days] 
    10.20.112.19     | node008                  | OK       | -                  | 55:55:55:55:55:b1  | 2016-08-18 [42 days] 
    10.20.112.20     | node009                  | OK       | [ SAME AS ARP ]    | 55:55:55:55:55:9d  | 2016-03-06 [207 days]
    ....


Report of unassigned IP addresses (no hostnames):

    $ ./ipam-lite.py 10.20.112.0 22 my.dns.domain arp/arp.dat dhcp/dhcpd.conf -u
    Unassigned addresses:
    
       1: 10.20.112.11  
       1: 10.20.112.26  
       1: 10.20.112.29  
       1: 10.20.112.31  
       1: 10.20.112.41  
       4: 10.20.112.57   => 10.20.112.60  
       1: 10.20.112.64  
       5: 10.20.112.67   => 10.20.112.71  
       8: 10.20.112.73   => 10.20.112.80  
       9: 10.20.112.87   => 10.20.112.95  
       9: 10.20.112.104  => 10.20.112.112 
      15: 10.20.112.115  => 10.20.112.129 
       1: 10.20.112.198 
       7: 10.20.112.218  => 10.20.112.224 
       1: 10.20.112.227 
       4: 10.20.112.231  => 10.20.112.234 
      11: 10.20.112.246  => 10.20.113.0   
       1: 10.20.113.105 
       1: 10.20.113.171 
       3: 10.20.113.255  => 10.20.114.1   
       9: 10.20.114.55   => 10.20.114.63  
       9: 10.20.114.69   => 10.20.114.77  
       1: 10.20.114.90  
      11: 10.20.114.92   => 10.20.114.102 
       1: 10.20.114.107 
       7: 10.20.114.123  => 10.20.114.129 
      29: 10.20.114.131  => 10.20.114.159 
       2: 10.20.114.162  => 10.20.114.163 
       3: 10.20.114.168  => 10.20.114.170 
      28: 10.20.114.173  => 10.20.114.200 
       3: 10.20.114.203  => 10.20.114.205 
      11: 10.20.114.220  => 10.20.114.230 
      25: 10.20.114.232  => 10.20.115.0   
       1: 10.20.115.26  
       3: 10.20.115.32   => 10.20.115.34  
       8: 10.20.115.64   => 10.20.115.71  
       6: 10.20.115.205  => 10.20.115.210 
       8: 10.20.115.212  => 10.20.115.219 
    
    Total unassigned: 250 / 1022



## TODO

* highlight mismatch between MAC address in DHCP and last reported MAC in
  Arpwatch
* make the Arpwatch parts of the report optional
* nicely highlight *old* hosts; those with no recent Arpwatch entry (for
  some value of *recent*)
* IPv6 support

