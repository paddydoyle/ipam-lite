from ipam_lite import canonicalise_mac

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
