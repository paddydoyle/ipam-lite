#!/usr/bin/python

import smtplib
import re
import sys
import subprocess
import ConfigParser
from datetime import date
import argparse
from netaddr import EUI
from netaddr import core
from netaddr import IPNetwork
from netaddr import mac_unix
import pprint
import socket
from datetime import datetime
from datetime import date



####################################################
# vars
####################################################

config_file    = 'config.ini'
#data_file      = 'data.ini'
arp_file       = 'arp/arp.dat'
dhcp_file      = 'dhcp/dhcpd.conf'

####################################################



####################################################
# read the filenames from cmd-line
####################################################

parser = argparse.ArgumentParser()
#parser.add_argument("address_file", help="CSV file containing the list of names and addresses")
#parser.add_argument("message_file", help="text file (with tokens) containing the email body text")
parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
#parser.add_argument("-d", "--dpgt", help="specify that the mails are to be addressed to DPGT",
#                    action="store_true")
parser.add_argument("-e", "--errors", help="display parsing and resolution errors",
                    action="store_true")
args = parser.parse_args()

if args.verbose:
   print "verbosity turned on"



####################################################
# main
####################################################
def main():
    # list of error messages
    error_list = []

    # read the config file
    config = parse_config()

    # read the arp entries
    arp_entries = parse_arp_file(arp_file, error_list)

    # read the dhcp entries
    dhcp_entries = parse_dhcp_file(config, dhcp_file, error_list)

    # loop
    main_report(config, arp_entries, dhcp_entries, error_list)

    if args.errors and len(error_list):
        display_errors(error_list)


def main_report(config, arp_entries, dhcp_entries, error_list):
    'loop over all of the addresses in the range'

    # current timestamp
    date_now = datetime.now()

    net = IPNetwork('%s/%s' % (config.get('Network', 'v4address'), config.get('Network', 'v4mask')))

    reverse_lookups = {}
    forward_lookups = {}

    for ip in net.iter_hosts():
        ip = str(ip)

        if args.verbose:
            print '%s' % ip

        host = ''
        resolved_ip = ''

        # look up the hostname
        try:
            res = socket.gethostbyaddr( ip )

            if args.verbose:
                print "found" + str(res)

            host = res[0]
            reverse_lookups[ip] = host

        except socket.error:
            if args.verbose:
                print "unable to reverse look up " + ip

        # now resolve the IP
        if host:
            try:
                resolved_ip = socket.gethostbyname(host)

                forward_lookups[host] = resolved_ip
            except socket.error:
                print "unable to forward look up " + host
                resolved_ip = record_error(error_list, "DNS: unable to forward look up " + host)

        #if resolved_ip and ip != resolved_ip:
        #    print "warning: %s != %s" % (ip, resolved_ip)

    #print "\nall forward lookups:\n"
    #for host in forward_lookups:
    #    print '  {0:20} ==> {1:20}'.format(host, forward_lookups[host])

    #for ip in reverse_lookups:
    #    print '  {0:20} ==> {1:20}'.format(ip, reverse_lookups[ip])

    # TODO: split the function here? create a dict of dicts of the entries?


    print "IPAM-Lite Report for %s\n" % net

    # IP -> host -> IP (match y/n) -> MAC (DHCP) -> MAC (ARP) -> timestamp (ARP)
    format_str = '{0:16} | {1:24} | {2:8} | {3:18} | {4:18} | {5:21}'

    # print the report headers
    print format_str.format('IP', 'Host', 'Host->IP', 'MAC (DHCP)', 'MAC (ARP)', 'Last seen (ARP)')
    print format_str.format('-' * 16, '-' * 24, '-' * 8, '-' * 18, '-' * 18, '-' * 21)

    for ip in net.iter_hosts():
        ip = str(ip)

        # did we have a hostname?
        if not ip in reverse_lookups:
            host = '-'
            resolved_ip = '-'
        else:
            host = reverse_lookups[ip]

        if not host in forward_lookups:
            resolved_ip = '-'
        else:
            resolved_ip = forward_lookups[host]

        # does the hostname resolve back to the same IP?
        if ip == resolved_ip:
            resolved_ip = 'OK'
        elif host == '-':
            resolved_ip = '-'
        else:
            resolved_ip = record_error(error_list, 'DNS: forward and reverse lookup mismatch for %s => %s => %s' % (ip, host, resolved_ip))

        # do we have a hostname in the dhcp entries? first change to short hostname
        if host != '-' and host.endswith(config.get('Network', 'domain')):
            short_host = host[:-len(config.get('Network', 'v4address'))]
            # only print the short hostname if it's in the domain
            host = short_host

            if short_host in dhcp_entries:
                mac_dhcp = dhcp_entries[short_host]
            else:
                mac_dhcp = '-'

        else:
            short_host = '-'
            mac_dhcp = '-'

        # do we have an entry in arp?
        if ip in arp_entries:
            mac_arp  = arp_entries[ip]['mac']
            host_arp = arp_entries[ip]['host']
            ts_arp   = arp_entries[ip]['ts']
        else:
            mac_arp  = '-'
            host_arp = '-'
            ts_arp   = '-'

        # matching MAC addresses?
        if mac_dhcp != '-' and mac_dhcp == mac_arp:
            mac_dhcp = "[ SAME AS ARP ]"

        if ts_arp != '-':
            date_arp = datetime.fromtimestamp(int(ts_arp))
            #ts_arp = date_arp.strftime('%Y-%m-%d %H:%M:%S')
            ts_arp = date_arp.strftime('%Y-%m-%d')

            delta = date_now - date_arp
            # TODO: configurable parameter of how many days?
            if delta.days > 1:
                ts_arp += ' [%d days]' % delta.days

        #print '  {0:16} | {1:30} | {2:4}'.format(ip, host, resolved_ip)
        print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)


# Parse the config
def parse_config():
    'Parse the config file'

    config = ConfigParser.RawConfigParser()
    config.read(config_file)


    if args.verbose:
        print "config:\n"
        for section in config.sections():
            print "section name: " + section
            print config.items(section)

    return config


# Parse the dhcpd.conf file
def parse_dhcp_file(config, dhcp_file, error_list):
    'Parse the dhcpd.conf file'

    # TODO: exclude blank lines and comments
    dhcp_entries = {}

    try:
        f = open(dhcp_file,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading dhcp file " + dhcp_file

    for fline in f:
        fline = fline.strip()
        if re.match('^$',fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#',fline):
            #print 'skipped a comment line'
            continue

        # try match the main regex
        # host tcin01 { hardware ethernet 00:30:48:7c:9b:ee;
        #matched = re.match('^\s*host\s+(\S+) \{\s*hardware\s*ethernet\s*(\S+)',fline)
        matched = re.match('^\s*host\s+(\S+) \{\s*hardware\s*ethernet\s*([0-9a-fA-F:]+)',fline)

        if matched:
            host = matched.group(1)
            mac  = canonicalise_mac(matched.group(2), error_list)

            # store the short hostname only
            if host != '-' and host.endswith(config.get('Network', 'domain')):
                short_host = host[:-len(config.get('Network', 'v4address'))]
                host = short_host

            dhcp_entries[host] = mac;

            if args.verbose:
                print "%s => %s" % (host, mac)

    f.close()

    #for e in dhcp_entries:
    #    print '%s => %s' % (e, str(dhcp_entries[e]))

    return dhcp_entries


# Parse the arp.dat file
def parse_arp_file(arp_file, error_list):
    'Parse the arp.dat file'

    arp_entries = {}
    try:
        f = open(arp_file,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading arp file " + arp_file

    for fline in f:
        fline = fline.strip()
        if re.match('^$',fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#',fline):
            #print 'skipped a comment line'
            continue

        #addr_list.append(fline.split(','))
        # 2:0:ac:10:1:f 134.226.115.150 1444404183  dri-guest020
        entry_list = fline.split()

        mac  = canonicalise_mac(entry_list[0], error_list)
        ip   = entry_list[1]
        ts   = entry_list[2]
        host = entry_list[3] if len(entry_list) > 3 else ''

        if args.verbose:
            print '%s' % entry_list

        # check for duplicate entries for the IP address; only store the most recent
        if not ip in arp_entries or int(arp_entries[ip]['ts']) < int(ts):
            arp_entries[ip] = {
                'mac': mac,
                'ts': ts,
                'host': host,
            }

    f.close()

    #for e in arp_entries:
    #    print '%s => %s' % (e, str(dhcp_entries[e]))

    return arp_entries


def record_error(error_list, message):
    'Store the error string, and return the index into the error array'
    error_list.append(message)
    return 'ERR%d' % (len(error_list)-1)


def display_errors(error_list):
    'Loop and print from the array'

    print "\nErrors:\n"

    for idx,err in enumerate(error_list):
        print 'ERR%-5d %s' % (idx, err)


def canonicalise_mac(mac_str, error_list):
    'Standardise on the MAC address format'

    # the 'mac_unix_expanded' format is only in a later version of the netaddr module
    # create a custom format
    class mac_custom(mac_unix): pass
    mac_custom.word_fmt = '%.2x'

    try:
        mac = EUI(mac_str, dialect=mac_custom)
        #mac.dialect = mac_unix_expanded
        #mac.dialect = mac_unix
    except core.AddrFormatError:
        #print "ERROR: unable to parse '%s' as a MAC address; skipping" % mac_str
        #return ''

        # assuming that the entries in arp.dat will always be validly formed, so MAC issues are dhcp
        return record_error(error_list, "DHCP: unable to parse '%s' as a MAC address" % mac_str)

    # return a string
    return '%s' % mac


if __name__ == '__main__':
    main()

