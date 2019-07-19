from ipam_lite import canonicalise_mac
from ipam_lite import parse_arp_file
from ipam_lite import parse_dhcp_file
from ipam_lite import parse_dns_entries

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
                "machine1.foo.com.           1800 IN A   10.20.112.113",
                "113.112.20.10.in-addr.arpa. 1800 IN PTR machine1.foo.com.",
                "machine222.foo.com.           1800 IN A   10.20.112.114",
                "114.112.20.10.in-addr.arpa. 1800 IN PTR machine2.foo.com.",
                "115.112.20.10.in-addr.arpa. 1800 IN PTRRRR machine2.foo.com.",
                "bob",
               ]
    error_list = []
    expected_values = {}

    ip1 = "10.20.112.113"
    host1 = "machine1.foo.com"
    expected_values[ip1] = (host1, ip1)

    ip2 = "10.20.112.114"
    host2 = "machine2.foo.com"
    expected_values[ip2] = (host2, "-")

    #### When ####
    dns_entries = parse_dns_entries(dns_text, error_list)

    #### Then ####
    assert(dns_entries[ip1] == expected_values[ip1])
    assert(dns_entries[ip2] == expected_values[ip2])

    assert(error_list[0] == "DNS: unexpected RR type: PTRRRR")
    assert(error_list[1] == "DNS: to parse DNS entry: bob")


###################################################
# DHCP parsing tests
###################################################

def test_parse_dhcp_file():
    #### Given ####
    dhcp_file = "test_data/dhcpd.txt"
    domain = "foo.com"
    dhcp_hostnames = False
    error_list = []

    host1 = "host001"
    mac1 = "50:00:00:00:33:09"

    host8 = "host008"
    mac8 = "50:00:00:0e:22:dde"

    host9 = "host009"
    mac9 = "50:00:00:0e:51:"

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
# DHCP parsing tests
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
