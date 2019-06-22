#!/usr/bin/env python

import argparse
import re
import socket
from datetime import datetime
from netaddr import EUI
from netaddr import core
from netaddr import IPNetwork
from netaddr import mac_unix

##############################################################################
# ipam_lite
# 2016-08-22 paddy@tchpc.tcd.ie
# For a given (IPv4) subnet, resolve the IP addresses and hostnames, looking
# for simple errors. Additionally, parse dhcpd.conf and arp.dat looking for
# other simple issues.
# Print out a nice report of the IP usage in the subnet, including 'last seen'
# dates from arpwatch.
##############################################################################





####################################################
# main
####################################################
def main():
    # list of error messages
    error_list = []

    # read the dns entries, unless we're told to resolve on the fly
    dns_entries = []
    if not args.resolve:
        dns_entries = parse_dns_file(error_list)

    # TODO: parse or resolve the DNS before calling the unassigned report

    # short report: just the ranges of unassigned addresses
    if args.unassigned:
        # TODO: pass dns_entries here
        unassigned_addresses_report()
        return None

    # read the arp entries
    arp_entries = parse_arp_file(error_list)

    # read the dhcp entries
    dhcp_entries = parse_dhcp_file(error_list)

    # loop
    main_report(arp_entries, dhcp_entries, dns_entries, error_list)

    if args.errors and error_list:
        display_errors(error_list)


def unassigned_addresses_report(dns_entries):
    'loop over all of the addresses in the range, printing a report of unassigned IP addresses'
    # TODO: split into two functions: work and report

    net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

    unassigned_list_of_lists = []

    count_unassigned = 0
    prev_ip_in_list = ''

    for ip in net.iter_hosts():
        ip_str = str(ip)

        # try to resolve the IP address
        try:
            res = socket.gethostbyaddr(ip_str)

            # it resolved ok, so clear this var
            prev_ip_in_list = ''

        except socket.error:
            count_unassigned += 1

            if not unassigned_list_of_lists or not prev_ip_in_list:
                # the very first unassigned address, or no prev_ip_in_list
                unassigned_list_of_lists.append([ip])
            elif prev_ip_in_list and (int(prev_ip_in_list)+1) == int(ip):
                # we're one address further on from previous one found, so append to the subnet
                unassigned_list_of_lists[-1].append(ip)

            # move on the saved var
            prev_ip_in_list = ip

    print 'Unassigned address blocks:\n'
    print 'Count: Range'

    for list_ in unassigned_list_of_lists:
        if len(list_) == 1:
            print '%5d: %-16s' % (1, list_[0])
        else:
            print '%5d: %-16s => %-16s' % (len(list_), list_[0], list_[-1])

    print "\nTotal unassigned: %d / %d" % (count_unassigned, (len(net) - 2))


def resolve_dns_entries_via_lookup(net, error_list):
    'loop over all of the addresses in the range, generating forward and reverse hashes'

    reverse_lookups = {}
    forward_lookups = {}

    count_assigned = 0

    for ip in net.iter_hosts():
        ip = str(ip)

        if args.verbose:
            print str(ip)

        host = ''
        resolved_ip = ''

        # try to resolve the IP address
        try:
            res = socket.gethostbyaddr(ip)

            if args.verbose:
                print "found" + str(res)

            host = res[0]
            reverse_lookups[ip] = host

            count_assigned += 1

        except socket.error:
            if args.verbose:
                print "unable to reverse look up " + ip

        # now try to resolve the hostname
        if host:
            try:
                resolved_ip = socket.gethostbyname(host)

                forward_lookups[host] = resolved_ip
            except socket.error:
                #print "unable to forward look up " + host
                # FIXME: put this into forward_lookups?
                resolved_ip = record_error(error_list, "DNS: unable to forward look up " + host)

    # return a dict of the three things we want to return:
    #   count_assigned: int
    #   reverse_lookups: hash
    #   forward_lookups: hash
    # TODO: change this to a tuple; we consume them immediately
    return {
        'count_assigned': count_assigned,
        'reverse_lookups': reverse_lookups,
        'forward_lookups': forward_lookups,
        }


def parse_dns_entries(dns_entries, error_list):
    'parse the dns entries from the list, generating forward and reverse hashes'

    reverse_lookups = {}
    forward_lookups = {}

    count_assigned = 0

    for line in dns_entries:

        # each line will be either:
        # machine1.foo.com.                        1800 IN A         10.20.112.113
        # 113.112.20.10.in-addr.arpa.              1800 IN PTR       machine1.foo.com.

        matched = re.match('^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.*)', line)

        if matched:
            dns_name = matched.group(1)
            dns_type = matched.group(2)
            dns_rdata = matched.group(3)

            if dns_type == 'A':
                # machine1.foo.com.                        1800 IN A         10.20.112.113

                # strip the trailing '.'
                if dns_name.endswith('.'):
                    dns_name = dns_name[:-1]

                forward_lookups[dns_name] = dns_rdata

            elif dns_type == 'PTR':
                # 113.112.20.10.in-addr.arpa.              1800 IN PTR       machine1.foo.com.

                # reverse the octets to retrieve the IP address
                octets = dns_name.split('.')[0:4]
                octets.reverse()
                ip = '.'.join(octets)

                # strip the trailing '.'
                if dns_rdata.endswith('.'):
                    dns_rdata = dns_rdata[:-1]

                reverse_lookups[ip] = dns_rdata

                count_assigned += 1
            else:
                record_error(error_list, "DNS: unexpected RR type: " + dns_type)
        else:
            record_error(error_list, "DNS: to parse DNS entry: " + line)

    # return a dict of the three things we want to return:
    #   count_assigned: int
    #   reverse_lookups: hash
    #   forward_lookups: hash
    # TODO: change this to a tuple; we consume them immediately
    return {
        'count_assigned': count_assigned,
        'reverse_lookups': reverse_lookups,
        'forward_lookups': forward_lookups,
        }


def main_report(arp_entries, dhcp_entries, dns_entries, error_list):
    'loop over all of the addresses in the range, printing a report'
    # TODO: split into two functions: work and report

    # current timestamp
    date_now = datetime.now()

    net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

    reverse_lookups = {}
    forward_lookups = {}

    count_assigned = 0
    count_no_arp = 0
    count_old_arp = 0

    if not args.resolve:
        # parse the DNS records from the flat dns_entries list into the hashes
        resolved_entries_dict = parse_dns_entries(dns_entries, error_list)
    else:
        # generate the hashes of resolved DNS entries
        resolved_entries_dict = resolve_dns_entries_via_lookup(net, error_list)

    count_assigned = resolved_entries_dict['count_assigned']
    reverse_lookups = resolved_entries_dict['reverse_lookups']
    forward_lookups = resolved_entries_dict['forward_lookups']


    # print the top header
    print "IPAM-Lite Report for %s\n" % net

    if args.no_arp:
        print("Filtering the report to show IP address with no ARP entries\n")
    if args.no_arp_days:
        print("Filtering the report to show IP address with no ARP entries in "
              "the past %d days\n" % (args.no_arp_days))

    # IP -> host -> IP (match y/n) -> MAC (DHCP) -> MAC (ARP) -> timestamp (ARP)
    format_str = '{0:16} | {1:24} | {2:8} | {3:18} | {4:18} | {5:21}'

    # print the report headers
    print format_str.format('IP', 'Host', 'Host->IP', 'MAC (DHCP)', 'MAC (ARP)', 'Last seen (ARP)')
    print format_str.format('-' * 16, '-' * 24, '-' * 8, '-' * 18, '-' * 18, '-' * 21)

    # main print loop over all the entries in the IP subnet
    for ip in net.iter_hosts():
        ip = str(ip)

        # did we have a hostname?
        if ip not in reverse_lookups:
            host = '-'
            resolved_ip = '-'
        else:
            host = reverse_lookups[ip]

        if host not in forward_lookups:
            resolved_ip = '-'
        else:
            resolved_ip = forward_lookups[host]

        # does the hostname resolve back to the same IP?
        if ip == resolved_ip:
            resolved_ip = 'OK'
        elif host == '-':
            resolved_ip = '-'
        else:
            resolved_ip = record_error(error_list,
                                       'DNS: forward and reverse lookup mismatch '
                                       'for %s => %s => %s' % (ip, host, resolved_ip))

        # do we have a hostname in the dhcp entries? first change to short hostname
        if host != '-' and host.endswith(args.domain):
            # add 1 to also remove the '.' between host and domain
            short_host = host[:-(len(args.domain)+1)]
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
            mac_arp = arp_entries[ip]['mac']
            host_arp = arp_entries[ip]['host']
            ts_arp = arp_entries[ip]['ts']
        else:
            mac_arp = '-'
            host_arp = '-'
            ts_arp = '-'

        # matching MAC addresses?
        if mac_dhcp != '-' and mac_dhcp == mac_arp:
            mac_dhcp = "[ SAME AS ARP ]"

        # reset, because of conditional update below
        delta = None

        if ts_arp != '-':
            date_arp = datetime.fromtimestamp(int(ts_arp))
            ts_arp = date_arp.strftime('%Y-%m-%d')

            count_no_arp += 1

            delta = date_now - date_arp
            # TODO: configurable parameter of how many days?
            if delta.days > 1:
                ts_arp += ' [%d days]' % delta.days

                if delta.days > args.no_arp_days:
                  count_old_arp += 1

        # any restrictions on the printing? limit to ones with no arp entries?
        if args.no_arp and ts_arp == '-':
            print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)
        elif args.no_arp_days and delta and delta.days > args.no_arp_days:
            print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)
        elif not args.no_arp and not args.no_arp_days:
            # no restrictions, print everything
            print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)

    print ""
    print "Total addresses in the range:          %4d" % (len(net) - 2)
    print "Total addresses with hostnames:        %4d" % (count_assigned)
    print "Total without ARP entries:             %4d" % (count_no_arp)
    if args.no_arp_days:
        print "Total ARP entries older than %d days: %4d" % (args.no_arp_days, count_old_arp)


# Parse the dhcpd.conf file
def parse_dhcp_file(error_list):
    'Parse the dhcpd.conf file'

    dhcp_entries = {}

    try:
        dhcp_file = open(args.dhcp_file, 'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading dhcp file " + args.dhcp_file

    for fline in dhcp_file:
        fline = fline.strip()
        if re.match('^$', fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#', fline):
            #print 'skipped a comment line'
            continue

        # try match the main regex
        # host foo01 { hardware ethernet 01:33:48:7c:9b:ae;
        matched = re.match('^\s*host\s+(\S+) \{\s*hardware\s*ethernet\s*([0-9a-fA-F:]+)', fline)

        if matched:
            host = matched.group(1)
            mac = canonicalise_mac(matched.group(2))

            if not mac:
                mac = record_error(error_list,
                                   "DHCP: unable to parse '%s' as a MAC address for %s"
                                   % (matched.group(2), host))

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


            dhcp_entries[host] = mac

            if args.verbose:
                print "%s => %s" % (host, mac)

    dhcp_file.close()

    return dhcp_entries


# Parse the exported dns file
def parse_dns_file(error_list):
    'Parse the exported dns file'

    dns_entries = []

    try:
        dns_file = open(args.dns_file, 'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading dns file " + args.dns_file

    for fline in dns_file:
        fline = fline.strip()

        # shouldn't be any comments or blank links in a dumped dns file, but just in case
        if re.match('^$', fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#', fline):
            #print 'skipped a comment line'
            continue

        # parse either a forward A record, or reverse PTR record
        # ignore other record types
        # no guarantee at all on the ordering of the dump file (might be lexical)
        # machine1.foo.com.                        1800 IN A         10.20.112.113
        # 113.112.20.10.in-addr.arpa.              1800 IN PTR       machine1.foo.com.
        # FIXME: do we care about RRs with multiple values, e.g. round-robin A records?
        matched = re.match('^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.*)', fline)

        if matched:
            dns_name = matched.group(1)
            dns_type = matched.group(2)
            dns_rdata = matched.group(3)

            # choosing not to process further into forward_lookups and reverse_lookups
            # here; we could, but then the return values from this function would be
            # propagated too early in the main function, and change up the code too
            # much. instead, put all of the lines into the list and return that for
            # processing later.

            if dns_type == 'A' or dns_type == 'PTR':
                dns_entries.append(fline)

                if args.verbose:
                    print "%s => %s => %s" % (dns_name, dns_type, dns_rdata)

    dns_file.close()

    return dns_entries


# Parse the arp.dat file
def parse_arp_file(error_list):
    'Parse the arp.dat file'

    arp_entries = {}
    try:
        arp_file = open(args.arp_file, 'r')
    except IOError, reason:
        print 'could not open file', str(reason)
        return None

    if args.verbose:
        print "Reading arp file " + args.arp_file

    for fline in arp_file:
        fline = fline.strip()
        if re.match('^$', fline):
            #print 'skipped a blank line'
            continue
        elif re.match('^\s*#', fline):
            #print 'skipped a comment line'
            continue

        #addr_list.append(fline.split(','))
        # 2:0:bd:10:3:f 10.15.115.150 1444404183  nmi-guest020
        entry_list = fline.split()

        mac = canonicalise_mac(entry_list[0])

        if not mac:
            mac = record_error(error_list,
                               "ARP: unable to parse '%s' as a MAC address for %s"
                               % (entry_list[0], entry_list[1]))

        ip = entry_list[1]
        ts = entry_list[2]
        host = entry_list[3] if len(entry_list) > 3 else ''

        if args.verbose:
            print str(entry_list)

        # check for duplicate entries for the IP address; only store the most recent
        if not ip in arp_entries or int(arp_entries[ip]['ts']) < int(ts):
            arp_entries[ip] = {
                'mac': mac,
                'ts': ts,
                'host': host,
            }

    arp_file.close()

    return arp_entries


def record_error(error_list, message):
    'Store the error string, and return the index into the error array'
    error_list.append(message)
    return 'ERR%d' % (len(error_list)-1)


def display_errors(error_list):
    'Loop and print from the array'

    print "\nErrors:\n"

    for idx, err in enumerate(error_list):
        print 'ERR%-5d %s' % (idx, err)


def canonicalise_mac(mac_str):
    'Standardise on the MAC address format'

    # the 'mac_unix_expanded' format is only in a later version of the netaddr module
    # create a custom format
    class MACCustom(mac_unix):
        pass

    MACCustom.word_fmt = '%.2x'

    try:
        mac = EUI(mac_str, dialect=MACCustom)
        #mac.dialect = mac_unix_expanded
        #mac.dialect = mac_unix
    except core.AddrFormatError:
        return ""

    # return a string
    return str(mac)


if __name__ == '__main__':

    ####################################################
    # read the filenames from cmd-line
    ####################################################

    # don't you just love argparse!!
    parser = argparse.ArgumentParser()
    # positional arguments
    parser.add_argument("netaddress", help="IPv4 network address")
    parser.add_argument("netmask", help="IPv4 network mask, in CIDR 'slash' notation")
    parser.add_argument("domain", help="default DNS domain name for hosts")
    parser.add_argument("arp_file",
                        help="the arp.dat file from arpwatch (typically "
                        "/var/lib/arpwatch/arp.dat)")
    parser.add_argument("dhcp_file",
                        help="the dhcpd.conf file (typically /etc/dhcpd/dhcpd.conf)")
    parser.add_argument("dns_file",
                        help="the dumped DNS entries (for example dumped from "
                        "'named-compilezone -f raw -F text'), forward and "
                        "reverse zones in a single file")
    # options
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-d", "--dhcp_hostnames",
                        help="check for hostnames in DHCP which don't resolve",
                        action="store_true")
    parser.add_argument("-e", "--errors", help="display parsing and resolution errors",
                        action="store_true")
    parser.add_argument("-u", "--unassigned",
                        help="only display lists of unassigned/free IP addresses",
                        action="store_true")
    parser.add_argument("-n", "--no_arp",
                        help="only display list of IP addresses with no ARP entries",
                        action="store_true")
    parser.add_argument("-N", "--no_arp_days",
                        help="only display list of IP addresses with no ARP entries in "
                        "the last N days",
                        type=int)
    parser.add_argument("-r", "--resolve",
                        help="look up hostnames on the fly, intead of reading entries "
                        "from a dumped file; ignore 'dns_file' in this case",
                        action="store_true")
    args = parser.parse_args()

    ####################################################
    # call main
    ####################################################
    main()


# vim: tabstop=4 expandtab
