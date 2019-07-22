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


def main(args):
    """Decide which report to run, based on the args."""
    error_list = []

    # Read the dns entries, unless we're told to resolve on the fly
    dns_entries = construct_dns_entries(args, error_list)

    # Short report: just the ranges of unassigned addresses
    if args.unassigned:
        unassigned_addresses_report(args, dns_entries)
        return None

    arp_entries = parse_arp_file(args.arp_file, error_list)

    dhcp_entries = parse_dhcp_file(args.dhcp_file, args.domain,
                                   args.dhcp_hostnames, error_list)

    main_report(args, arp_entries, dhcp_entries, dns_entries, error_list)

    if args.errors and error_list:
        error_report(error_list)


def construct_dns_entries(args, error_list):
    """Construct dict of dns entries, either by live resolving, or
    by parsing dumped BIND-style DNS files.
    """

    if args.resolve:
        net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

        # Generate the dict of resolved DNS entries, via live lookup
        return resolve_dns_entries_via_lookup(net, error_list)
    else:
        raw_dns_entries = parse_dns_file(args.dns_file)

        # Parse the DNS records from the flat raw_dns_entries list into
        # the dict of DNS entries
        return parse_dns_entries(raw_dns_entries, error_list)


def unassigned_addresses_report(args, dns_entries):
    """Loop over all of the addresses in the range, printing a report of
    unassigned IP addresses in contiguous blocks."""

    (count_unassigned,
     count_addresses,
     unassigned_blocks) = unassigned_addresses_generate(args, dns_entries)

    print 'Unassigned address blocks:\n'
    print 'Count: Range'

    for unassigned_block in unassigned_blocks:
        if len(unassigned_block) == 1:
            print '%5d: %-16s' % (1, unassigned_block[0])
        else:
            print '%5d: %-16s => %-16s' % (len(unassigned_block),
                                           unassigned_block[0],
                                           unassigned_block[-1])

    print "\nTotal unassigned: %d / %d" % (count_unassigned, count_addresses)


def unassigned_addresses_generate(args, dns_entries):
    """Loop over all of the addresses in the range. Return a list of
    unassigned IP addresses in contiguous blocks."""

    net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

    unassigned_blocks = []

    count_unassigned = 0
    prev_ip_in_block = ''

    for ip in net.iter_hosts():
        if str(ip) in dns_entries:
            # It resolved ok, so clear this var
            prev_ip_in_block = ''
        else:
            count_unassigned += 1

            if not unassigned_blocks or not prev_ip_in_block:
                # The very first unassigned address, or no prev_ip_in_block
                unassigned_blocks.append([ip])
            elif prev_ip_in_block and (int(prev_ip_in_block)+1) == int(ip):
                # We're one address further on from previous one found, so
                # append to the block
                unassigned_blocks[-1].append(ip)

            # Move on the saved var
            prev_ip_in_block = ip

    count_addresses = len(net) - 2

    return (count_unassigned, count_addresses, unassigned_blocks)


def resolve_dns_entries_via_lookup(net, error_list):
    """Loop over all of the IP addresses in the range. Return a dict of entries,
    keyed on the IP address."""

    dns_entries = {}

    for ip in net.iter_hosts():
        ip = str(ip)

        # Try to resolve the IP address
        host = dns_reverse_lookup(ip)

        # Skip forward lookup if the reverse lookup failed.
        if not host:
            continue

        # Now try to resolve the hostname
        resolved_ip = dns_forward_lookup(host)

        if resolved_ip:
            dns_entries[ip] = (host, resolved_ip)
        else:
            dns_entries[ip] = (host, '-')
            record_error(error_list, "DNS: unable to forward look up " + host)

    return dns_entries


def dns_reverse_lookup(ip):
    """Reverse query of IP Address. Return hostname if found."""
    try:
        return socket.gethostbyaddr(ip)[0]

    except socket.error:
        pass


def dns_forward_lookup(host):
    """Forward query of hostname. Return IP address if found."""
    try:
        return socket.gethostbyname(host)

    except socket.error:
        pass


def parse_dns_entries(raw_dns_entries, error_list):
    """Parse the dns entries from the list. Return a dict of entries,
    keyed on the IP address."""
    reverse_lookups = {}
    forward_lookups = {}
    dns_entries = {}

    # First pass at the data: extract A and PTR records. The input
    # ordering is not known.
    for line in raw_dns_entries:

        # Each line will be either:
        # machine1.foo.com.                        1800 IN A         10.20.112.113
        # 113.112.20.10.in-addr.arpa.              1800 IN PTR       machine1.foo.com.

        matched = re.match(r'^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.*)', line)

        if not matched:
            record_error(error_list, "DNS: to parse DNS entry: " + line)
            continue

        dns_name = matched.group(1)
        dns_type = matched.group(2)
        dns_rdata = matched.group(3)

        if dns_type == 'A':
            # Sample text input:
            # machine1.foo.com.                        1800 IN A         10.20.112.113

            # Strip the trailing '.'
            if dns_name.endswith('.'):
                dns_name = dns_name[:-1]

            forward_lookups[dns_name] = dns_rdata

        elif dns_type == 'PTR':
            # Sample text input:
            # 113.112.20.10.in-addr.arpa.              1800 IN PTR       machine1.foo.com.

            # Reverse the octets to retrieve the IP address
            # FIXME: can we do better with slice in reverse?
            octets = dns_name.split('.')[0:4]
            octets.reverse()
            ip = '.'.join(octets)

            # Strip the trailing '.'
            if dns_rdata.endswith('.'):
                dns_rdata = dns_rdata[:-1]

            reverse_lookups[ip] = dns_rdata
        else:
            record_error(error_list, "DNS: unexpected RR type: " + dns_type)

    # Second pass at the data. Not great, but the order of the entries
    # is not known during the first pass.
    # This pass, for each of the found IP addresses, check if the forward
    # lookup of its host is there.
    for ip, host in reverse_lookups.items():
        if host in forward_lookups:
            dns_entries[ip] = (host, forward_lookups[host])
        else:
            dns_entries[ip] = (host, '-')

    return dns_entries


def format_dns_entry(ip, dns_entries, error_list):
    """Format the DNS parts of the main report. Return a
    tuple of the host and its resolved IP."""

    # Did we have a hostname?
    if ip in dns_entries:
        (host, resolved_ip) = dns_entries[ip]
    else:
        (host, resolved_ip) = ('-', '-')

    # Does the hostname resolve back to the same IP?
    if ip == resolved_ip:
        resolved_ip = 'OK'
    elif host == '-':
        resolved_ip = '-'
    else:
        resolved_ip = record_error(error_list,
                                   'DNS: forward and reverse lookup mismatch '
                                   'for %s => %s => %s' % (ip, host, resolved_ip))

    return (host, resolved_ip)

def main_report(args, arp_entries, dhcp_entries, dns_entries, error_list):
    """Loop over all of the addresses in the range, printing a report."""
    # TODO: split into two functions: work and report

    # Current timestamp
    date_now = datetime.now()

    net = IPNetwork('%s/%s' % (args.netaddress, args.netmask))

    count_arp_entries = 0
    count_old_arp = 0

    # Top header
    print "IPAM-Lite Report for %s\n" % net

    if args.no_arp:
        print("Filtering the report to show IP address with no ARP entries\n")
    if args.no_arp_days:
        print("Filtering the report to show IP address with no ARP entries in "
              "the past %d days\n" % (args.no_arp_days))

    # IP -> host -> IP (match y/n) -> MAC (DHCP) -> MAC (ARP) -> timestamp (ARP)
    format_str = '{0:16} | {1:24} | {2:8} | {3:18} | {4:18} | {5:21}'

    # Report headers.
    print format_str.format('IP', 'Host', 'Host->IP', 'MAC (DHCP)', 'MAC (ARP)', 'Last seen (ARP)')
    print format_str.format('-' * 16, '-' * 24, '-' * 8, '-' * 18, '-' * 18, '-' * 21)

    # Main report loop: over all the entries in the IP subnet
    for ip in net.iter_hosts():
        ip = str(ip)

        (host, resolved_ip) = format_dns_entry(ip, dns_entries, error_list)

        # Do we have a hostname in the dhcp entries?
        if host != '-' and host.endswith(args.domain):
            # Change to short hostname.
            # Add 1 to also remove the '.' between host and domain
            short_host = host[:-(len(args.domain)+1)]
            # Only print the short hostname if it's in the domain
            host = short_host

            if short_host in dhcp_entries:
                mac_dhcp = dhcp_entries[short_host]
            else:
                mac_dhcp = '-'

        else:
            short_host = '-'
            mac_dhcp = '-'

        # Do we have an entry in arp?
        if ip in arp_entries:
            (mac_arp, ts_arp) = arp_entries[ip]
        else:
            (mac_arp, ts_arp) = ("-", "-")

        # Matching MAC addresses?
        if mac_dhcp != '-' and mac_dhcp == mac_arp:
            mac_dhcp = "[ SAME AS ARP ]"

        # Reset, because of conditional update below
        delta = None

        if ts_arp != '-':
            date_arp = datetime.fromtimestamp(int(ts_arp))
            ts_arp = date_arp.strftime('%Y-%m-%d')

            count_arp_entries += 1

            delta = date_now - date_arp
            # TODO: configurable parameter of how many days?
            if delta.days > 1:
                ts_arp += ' [%d days]' % delta.days

                if delta.days > args.no_arp_days:
                    count_old_arp += 1

        # Any restrictions on the printing? Limit to ones with no arp entries?
        if args.no_arp and ts_arp == '-':
            print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)
        elif args.no_arp_days and delta and delta.days > args.no_arp_days:
            print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)
        elif not args.no_arp and not args.no_arp_days:
            # No restrictions, print everything.
            print format_str.format(ip, host, resolved_ip, mac_dhcp, mac_arp, ts_arp)

    print ""
    print "Total addresses in the range:          %4d" % (len(net) - 2)
    print "Total addresses with hostnames:        %4d" % (len(dns_entries))
    print "Total with no ARP entries:             %4d" % (len(net) - 2 - count_arp_entries)
    if args.no_arp_days:
        print "Total ARP entries older than %d days: %4d" % (args.no_arp_days, count_old_arp)


# Parse the dhcpd.conf file
def parse_dhcp_file(dhcp_file, domain, dhcp_hostnames, error_list):
    """Parse the dhcpd.conf file. Return a dict of entries, keyed
    on the short hostname."""

    dhcp_entries = {}

    try:
        dhcp_file = open(dhcp_file, 'r')
    except IOError, reason:
        print 'Could not open file: ', str(reason)
        return None

    for fline in dhcp_file:
        fline = fline.strip()
        if re.match(r'^$', fline):
            continue
        elif re.match(r'^\s*#', fline):
            continue

        # Sample input string:
        # host foo01 { hardware ethernet 01:33:48:7c:9b:ae;
        matched = re.match(r'^\s*host\s+(\S+) \{\s*hardware\s*ethernet\s*([0-9a-fA-F:]+)', fline)

        if matched:
            host = matched.group(1)
            mac = canonicalise_mac(matched.group(2))

            if not mac:
                mac = record_error(error_list,
                                   "DHCP: unable to parse '%s' as a MAC address for %s"
                                   % (matched.group(2), host))

            # Store the short hostname only
            if host and host.endswith(domain):
                short_host = host[:-len(domain)]
                host = short_host

            # See if the hostname in DHCP still resolves
            if dhcp_hostnames:
                try:
                    _ = socket.gethostbyname('%s.%s' % (host, domain))

                except socket.error:
                    record_error(error_list, "DHCP: unable to resolve " + host)


            dhcp_entries[host] = mac

    dhcp_file.close()

    return dhcp_entries


def parse_dns_file(dns_file):
    """Parse the exported dns file. Return a list of raw text entries
    of relevant Resource Records types.
    """
    raw_dns_entries = []

    try:
        dns_file = open(dns_file, 'r')
    except IOError, reason:
        print 'Could not open file: ', str(reason)
        return None

    for fline in dns_file:
        fline = fline.strip()

        # Shouldn't be any comments or blank links in a dumped dns file, but
        # just in case.
        if re.match(r'^$', fline):
            continue
        elif re.match(r'^\s*#', fline):
            continue

        # Parse either a forward A record, or reverse PTR record.
        # Ignore other record types.
        # No guarantee at all on the ordering of the dump file (might be lexical)
        # machine1.foo.com.                        1800 IN A         10.20.112.113
        # 113.112.20.10.in-addr.arpa.              1800 IN PTR       machine1.foo.com.
        # FIXME: do we care about RRs with multiple values, e.g. round-robin A records?
        matched = re.match(r'^(\S+)\s+\d+\s+IN\s+(\S+)\s+(.*)', fline)

        if matched:
            dns_type = matched.group(2)

            # Choosing not to process further into forward_lookups and
            # reverse_lookups here. We could, but then the return values
            # from this function would be propagated too early in the main
            # function, and change up the code too much. Instead, put all
            # of the lines into the list and return that for processing
            # later.
            if dns_type == 'A' or dns_type == 'PTR':
                raw_dns_entries.append(fline)

    dns_file.close()

    return raw_dns_entries


def parse_arp_file(arp_file, error_list):
    """Parse the arp.dat file. Return a list of tuples."""
    arp_entries = {}
    try:
        arp_file = open(arp_file, 'r')
    except IOError, reason:
        print 'Could not open file: ', str(reason)
        return None

    for fline in arp_file:
        fline = fline.strip()
        if re.match(r'^$', fline):
            continue
        elif re.match(r'^\s*#', fline):
            continue

        # Sample input format:
        # 2:0:bd:10:3:f 10.15.115.150 1444404183  nmi-guest020
        entry_list = fline.split()

        mac = canonicalise_mac(entry_list[0])

        if not mac:
            mac = record_error(error_list,
                               "ARP: unable to parse '%s' as a MAC address for %s"
                               % (entry_list[0], entry_list[1]))

        ip = entry_list[1]
        ts = entry_list[2]

        # In case of duplicates, only store the most recent.
        if not ip in arp_entries or int(arp_entries[ip][1]) < int(ts):
            arp_entries[ip] = (mac, ts)

    arp_file.close()

    return arp_entries


def record_error(error_list, message):
    """Store the error string. Return the index into the error array."""
    error_list.append(message)
    return 'ERR%d' % (len(error_list)-1)


def error_report(error_list):
    """Print the error list."""
    print "\nErrors:\n"

    for idx, err in enumerate(error_list):
        print 'ERR%-5d %s' % (idx, err)


def canonicalise_mac(mac_str):
    """Standardise the MAC address format. Return a string."""
    # The 'mac_unix_expanded' format is only in a later version of the
    # netaddr module. Create a custom format.
    class MACCustom(mac_unix):
        pass

    MACCustom.word_fmt = '%.2x'

    try:
        mac = EUI(mac_str, dialect=MACCustom)
        #mac.dialect = mac_unix_expanded
        #mac.dialect = mac_unix
    except core.AddrFormatError:
        return ""

    return str(mac)


if __name__ == '__main__':

    ####################################################
    # Command-line args.
    ####################################################

    # Don't you just love argparse!!
    parser = argparse.ArgumentParser()
    # Positional arguments
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
    # Options
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
    # Call main
    ####################################################
    main(args)


# vim: tabstop=4 expandtab
