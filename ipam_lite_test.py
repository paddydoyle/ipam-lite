from ipam_lite import canonicalise_mac
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

    #### When ####
    dns_entries = parse_dns_entries(dns_text, error_list)

    #### Then ####
    ip1 = "10.20.112.113"
    host1 = "machine1.foo.com"
    expected_values[ip1] = (host1, ip1)

    assert(dns_entries[ip1] == expected_values[ip1])

    ip2 = "10.20.112.114"
    host2 = "machine2.foo.com"
    expected_values[ip2] = (host2, "-")

    assert(dns_entries[ip2] == expected_values[ip2])

    assert(error_list[0] == "DNS: unexpected RR type: PTRRRR")

    assert(error_list[1] == "DNS: to parse DNS entry: bob")


# TODO: test dhcp parsing
# TODO: test arp parsing
