#!/usr/bin/env python

import re
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

##############################################################################
# ipam-lite
# 2016-08-22 paddy@tchpc.tcd.ie
# For a given (IPv4) subnet, resolve the IP addresses and hostnames, looking
# for simple errors. Additionally, parse dhcpd.conf and arp.dat looking for
# other simple issues.
# Print out a nice report of the IP usage in the subnet, including 'last seen'
# dates from arpwatch.
##############################################################################



####################################################
# read the filenames from cmd-line
####################################################

# don't you just love argparse!!
parser = argparse.ArgumentParser()
# positional arguments
parser.add_argument("netaddress", help="IPv4 network address")
parser.add_argument("netmask", help="IPv4 network mask, in CIDR 'slash' notation")
parser.add_argument("domain", help="default DNS domain name for hosts")
parser.add_argument("arp_file", help="the arp.dat file from arpwatch (typically /var/lib/arpwatch/arp.dat)")
parser.add_argument("dhcp_file", help="the dhcpd.conf file (typically /etc/dhcpd/dhcpd.conf)")
# options
parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
parser.add_argument("-d", "--dhcp_hostnames", help="check for hostnames in DHCP which don't resolve",
                    action="store_true")
parser.add_argument("-e", "--errors", help="display parsing and resolution errors",
                    action="store_true")
parser.add_argument("-u", "--unassigned", help="only display lists of unassigned/free IP addresses",
                    action="store_true")
args = parser.parse_args()



####################################################
# main
####################################################
def main():
    # list of error messages
    error_list = []

    if args.unassigned:
        unassigned_addresses_report()
        return None

    # read the arp entries
    arp_entries = parse_arp_file(error_list)

    # read the dhcp entries
    dhcp_entries = parse_dhcp_file(error_list)

    # loop
    main_report(arp_entries, dhcp_entries, error_list)

    if args.errors and len(error_list):
        display_errors(error_list)


def unassigned_addresses_report():
    'loop over all of the addresses in the range, printing a report of unassigned IP addresses'

    net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

    unassigned_list_of_lists = []

    count_unassigned = 0
    prev_ip_in_list = ''

    for ip in net.iter_hosts():
        ip_str = str(ip)

        # look up the hostname
        try:
            res = socket.gethostbyaddr( ip_str )

            # it resolved ok, so clear this var
            prev_ip_in_list = ''

        except socket.error:
            #print '%s' % ip
            count_unassigned += 1

            if not unassigned_list_of_lists or not prev_ip_in_list:
                # the very first unassigned address, or no prev_ip_in_list
                unassigned_list_of_lists.append( [ip] )
            elif prev_ip_in_list and (int(prev_ip_in_list)+1) == int(ip):
                # we're one address further on from previous one found, so append to the subnet
                unassigned_list_of_lists[-1].append(ip)

            # move on the saved var
            prev_ip_in_list = ip

    print 'Unassigned addresses:\n'

    for l in unassigned_list_of_lists:
        #print "list: %s" % l
        if len(l) == 1:
            print '%4d: %-16s' % (1, l[0])
        else:
            print '%4d: %-16s => %-16s' % (len(l), l[0], l[-1])

    print "\nTotal unassigned: %d / %d" % (count_unassigned, (len(net) - 2))

def main_report(arp_entries, dhcp_entries, error_list):
    'loop over all of the addresses in the range, printing a report'

    # current timestamp
    date_now = datetime.now()

    net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

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
                #print "unable to forward look up " + host
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
        if host != '-' and host.endswith(args.domain):
            short_host = host[:-len(args.netaddress)]
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


# Parse the dhcpd.conf file
def parse_dhcp_file(error_list):
    'Parse the dhcpd.conf file'

    # TODO: exclude blank lines and comments
    dhcp_entries = {}

    try:
        f = open(args.dhcp_file,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading dhcp file " + args.dhcp_file

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
            if host != '-' and host.endswith(args.domain):
                short_host = host[:-len(args.domain)]
                host = short_host

            # see if the hostname in DHCP still resolves
            if args.dhcp_hostnames:
                try:
                    resolved_ip = socket.gethostbyname('%s.%s' % (host, args.domain))

                except socket.error:
                    #print "unable to forward look up " + host
                    record_error(error_list, "DHCP: unable to resolve " + host)


            dhcp_entries[host] = mac;

            if args.verbose:
                print "%s => %s" % (host, mac)

    f.close()

    #for e in dhcp_entries:
    #    print '%s => %s' % (e, str(dhcp_entries[e]))

    return dhcp_entries


# Parse the arp.dat file
def parse_arp_file(error_list):
    'Parse the arp.dat file'

    arp_entries = {}
    try:
        f = open(args.arp_file,'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading arp file " + args.arp_file

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


# vim: tabstop=4 expandtab
