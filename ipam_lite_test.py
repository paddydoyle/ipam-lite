from datetime import datetime

from ipam_lite import canonicalise_mac
from ipam_lite import parse_arp_file
from ipam_lite import parse_dhcp_file
from ipam_lite import parse_dns_entries
from ipam_lite import parse_dns_file
from ipam_lite import format_arp_entry
from ipam_lite import format_dhcp_entry
from ipam_lite import format_dns_entry
from ipam_lite import unassigned_addresses_generate

###################################################
# MAC parsing tests
###################################################

def test_canonicalise_mac_valid():
    mac = "de:ad:be:ef:00:01"
    assert(canonicalise_mac(mac) == mac)

def test_canonicalise_mac_upper():
    mac = "DE:AD:BE:EF:00:01"
    assert(canonicalise_mac(mac) == mac.lower())

def test_canonicalise_mac_dashed_input():
    mac = "DE-AD-BE-EF-00-01"
    assert(canonicalise_mac(mac) == mac.lower().replace("-", ":"))

def test_canonicalise_mac_missing_leading_zeros():
    mac = "2:0:bd:10:3:f"
    assert(canonicalise_mac(mac) == "02:00:bd:10:03:0f")

def test_canonicalise_mac_not_hex_input():
    mac = "ZZ:AD:TT:EF:00:01"
    assert(canonicalise_mac(mac) == "")

def test_canonicalise_mac_wrong_format():
    mac = "this is not a mac"
    assert(canonicalise_mac(mac) == "")

def test_canonicalise_mac_wrong_length():
    mac = "ZZ:AD:TT:EF:00"
    assert(canonicalise_mac(mac) == "")


###################################################
# DNS parsing tests
###################################################

def test_parse_dns_entries():
    #### Given ####
    dns_text = [
                "machine1.foo.com.           1800 IN A   10.10.15.1",
                "1.15.10.10.in-addr.arpa. 1800 IN PTR machine1.foo.com.",
                "machine222.foo.com.           1800 IN A   10.10.15.2",
                "2.15.10.10.in-addr.arpa. 1800 IN PTR machine2.foo.com.",
                "3.15.10.10.in-addr.arpa. 1800 IN PTRRRR machine2.foo.com.",
                "bob",
               ]
    error_list = []
    expected_values = {}

    ip1 = "10.10.15.1"
    host1 = "machine1.foo.com"
    expected_values[ip1] = (host1, ip1)

    ip2 = "10.10.15.2"
    host2 = "machine2.foo.com"
    expected_values[ip2] = (host2, "-")

    #### When ####
    dns_entries = parse_dns_entries(dns_text, error_list)

    #### Then ####
    assert(dns_entries[ip1] == expected_values[ip1])
    assert(dns_entries[ip2] == expected_values[ip2])

    assert(error_list[0] == "DNS: unexpected RR type: PTRRRR")
    assert(error_list[1] == "DNS: to parse DNS entry: bob")

def test_parse_dns_file():
    #### Given ####
    dns_file = "test_data/dns.txt"

    host_a1 = "host001.foo.com.    1800 IN A    10.10.15.1"
    host_ptr1 = "1.15.10.10.in-addr.arpa.    1800 IN PTR    host001.foo.com."

    #### When ####
    raw_dns_entries = parse_dns_file(dns_file)

    #### Then ####
    assert(host_a1 in raw_dns_entries)
    assert(host_ptr1 in raw_dns_entries)


###################################################
# DHCP parsing tests
###################################################

def test_parse_dhcp_file():
    #### Given ####
    dhcp_file = "test_data/dhcpd.txt"
    domain = "foo.com"
    dhcp_hostnames = False
    error_list = []

    # Good MAC
    host1 = "host001"
    mac1 = "50:00:00:00:33:09"

    # Bad MAC: too long
    host8 = "host008"
    mac8 = "50:00:00:0e:22:dde"

    # Bad MAC: too short
    host9 = "host009"
    mac9 = "50:00:00:0e:51:"

    # Good MAC
    host10 = "host010.foobar.com"
    mac10 = "50:00:00:0f:22:04"

    #### When ####
    dhcp_entries = parse_dhcp_file(dhcp_file, domain, dhcp_hostnames, error_list)

    #### Then ####
    assert(dhcp_entries[host1] == mac1)
    assert(dhcp_entries[host8] == "ERR0")
    assert(dhcp_entries[host9] == "ERR1")
    assert(dhcp_entries[host10] == mac10)

    assert(error_list[0] ==
           "DHCP: unable to parse '%s' as a MAC address for %s" % (mac8, host8))
    assert(error_list[1] ==
           "DHCP: unable to parse '%s' as a MAC address for %s" % (mac9, host9))


###################################################
# ARP parsing tests
###################################################

def test_parse_arp_file():
    #### Given ####
    arp_file = "test_data/arp.txt"
    error_list = []

    ip1 = "10.10.15.1"
    mac1 = "50:00:00:00:33:09"
    ts1 = "1561047705"

    ip8 = "10.10.15.8"
    mac8 = "ERR0"
    ts8 = "1457277442"

    ip10 = "10.10.15.10"
    mac10 = "50:00:00:0f:22:04"
    ts10 = "1457278560"

    #### When ####
    arp_entries = parse_arp_file(arp_file, error_list)

    #### Then ####
    assert(arp_entries[ip1] == (mac1, ts1))

    assert(arp_entries[ip8] == (mac8, ts8))

    assert(arp_entries[ip10] == (mac10, ts10))


###################################################
# DNS formatting tests
###################################################

def test_format_dns_entry():
    #### Given ####
    domain = "foo.com"
    error_list = []

    # Good entry
    ip1 = "10.10.15.1"
    host1 = "host001.foo.com"
    resolved_ip1 = ip1

    # Forward and reverse mismatch.
    ip2 = "10.10.15.10"
    host2 = "host010.foobar.com"
    resolved_ip2 = "10.10.10.10"

    # Missing from dns_entries
    ip3 = "10.10.15.20"
    resolved_ip3 = "10.10.10.20"

    dns_entries = {
                   ip1: (host1, resolved_ip1),
                   ip2: (host2, resolved_ip2),
                  }

    #### When ####
    (processed_host1, resolved_ip1) = format_dns_entry(ip1, dns_entries, domain, error_list)
    (processed_host2, resolved_ip2) = format_dns_entry(ip2, dns_entries, domain, error_list)
    (processed_host3, resolved_ip3) = format_dns_entry(ip3, dns_entries, domain, error_list)


    #### Then ####
    assert(resolved_ip1 == "OK")
    assert(resolved_ip2 == resolved_ip2)
    assert(resolved_ip2 == "ERR0")
    assert(resolved_ip3 == "-")
    assert(processed_host1 == host1[:-(len(domain)+1)])
    assert(processed_host2 == host2)
    assert(processed_host3 == "-")

    assert(error_list[0] ==
           "DNS: forward and reverse lookup mismatch for %s => %s => %s" % (ip2, host2, "10.10.10.10"))


###################################################
# DHCP formatting tests
###################################################

def test_format_dhcp_entry():
    #### Given ####
    # Good entry
    host1 = "host001"
    mac_dhcp1 = "50:00:00:00:33:09"
    mac_arp1 = "50:00:00:00:33:09"

    # Mismatch.
    host2 = "host007"
    mac_dhcp2 = "50:00:00:0e:22:95"
    mac_arp2 = "50:00:00:0e:11:e9"

    # Missing.
    host3 = "host020"
    mac_arp3 = ""

    dhcp_entries = {
                   host1: mac_dhcp1,
                   host2: mac_dhcp2,
                  }

    #### When ####
    mac_dhcp1 = format_dhcp_entry(host1, dhcp_entries, mac_arp1)
    mac_dhcp2 = format_dhcp_entry(host2, dhcp_entries, mac_arp2)
    mac_dhcp3 = format_dhcp_entry(host3, dhcp_entries, mac_arp3)


    #### Then ####
    assert(mac_dhcp1 == "[ SAME AS ARP ]")
    assert(mac_dhcp2 == "50:00:00:0e:22:95")
    assert(mac_dhcp3 == "-")


###################################################
# ARP formatting tests
###################################################

def test_format_arp_entry():
    #### Given ####
    # Good entry, same date.
    ip1 = "10.10.15.1"
    mac_arp1 = "50:00:00:00:33:09"
    ts_arp1 = datetime.now().strftime('%s')
    expected_ts_arp1 = datetime.now().strftime('%Y-%m-%d')

    # Good entry, days old.
    ip2 = "10.10.15.2"
    mac_arp2 = "50:00:00:08:3a:b8"
    ts_arp2 = 1561047705
    expected_ts_arp2 = datetime.fromtimestamp(ts_arp2)
    delta_arp2 = datetime.now() - expected_ts_arp2
    expected_ts_arp2 = expected_ts_arp2.strftime('%Y-%m-%d')
    expected_ts_arp2 += ' [%d days]' % delta_arp2.days

    # Missing.
    ip3 = "10.10.15.20"
    expected_mac_arp3 = "-"

    arp_entries = {
                   ip1: (mac_arp1, ts_arp1),
                   ip2: (mac_arp2, ts_arp2),
                  }

    #### When ####
    (mac_arp1, ts_arp1, delta_arp1) = format_arp_entry(ip1, arp_entries)
    (mac_arp2, ts_arp2, delta_arp2) = format_arp_entry(ip2, arp_entries)
    (mac_arp3, ts_arp3, delta_arp3) = format_arp_entry(ip3, arp_entries)


    #### Then ####
    assert(mac_arp1 == "50:00:00:00:33:09")
    assert(expected_ts_arp1 == ts_arp1)

    assert(expected_ts_arp2 == ts_arp2)

    assert(expected_mac_arp3 == "-")
    assert(delta_arp3 == None)


###################################################
# Unassigned blocks formatting tests
###################################################

def test_unassigned_addresses_generate():
    #### Given ####
    class ArgsMock:
        pass
    args = ArgsMock()
    args.netaddress = "10.10.15.0"
    args.netmask = "28"

    dns_entries = {
                   "10.10.15.1": ("", ""),
                   "10.10.15.2": ("", ""),
                   "10.10.15.3": ("", ""),
                   "10.10.15.6": ("", ""),
                   "10.10.15.7": ("", ""),
                   "10.10.15.8": ("", ""),
                   "10.10.15.9": ("", ""),
                   "10.10.15.10": ("", ""),
                  }

    #### When ####
    (count_unassigned,
     count_addresses,
     unassigned_blocks) = unassigned_addresses_generate(args, dns_entries)

    #### Then ####
    assert(count_unassigned == 6)
    assert(count_addresses == 14)

    assert(len(unassigned_blocks) == 2)
    assert(len(unassigned_blocks[0]) == 2)
    assert(len(unassigned_blocks[1]) == 4)
