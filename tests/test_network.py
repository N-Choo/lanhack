import unittest.mock, socket, struct
from lanhack.network import detect_network, fingerprint_device, DEVICE_TYPES

@unittest.mock.patch("subprocess.check_output")
def test_detect_network_ip_route(mock_subprocess):
    mock_subprocess.return_value = "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000"
    iface, ip, gw, netmask = detect_network()
    assert iface == "eth0"
    assert ip == "192.168.1.100"
    assert gw == "192.168.1.1"
    assert netmask == "192.168.1.0/24"

@unittest.mock.patch("subprocess.check_output")
def test_detect_network_different_ip(mock_subprocess):
    mock_subprocess.return_value = "1.1.1.1 via 10.0.0.1 dev wlan0 src 10.0.0.50 uid 1000"
    iface, ip, gw, netmask = detect_network()
    assert iface == "wlan0"
    assert ip == "10.0.0.50"
    assert gw == "10.0.0.1"
    assert netmask == "10.0.0.0/24"

def test_fingerprint_device_types():
    assert "Apple" in DEVICE_TYPES
    assert DEVICE_TYPES["Apple"] == "macOS/iOS"
    assert DEVICE_TYPES["Samsung"] == "Samsung"
    assert DEVICE_TYPES["Microsoft"] == "Windows"

def test_fingerprint_device_unknown():
    import lanhack.config as c
    c.devices = [{"ip":"192.168.1.50","mac":"","vendor":"Unknown","hostname":"","fingerprint":"","open_ports":""}]
    guess, ports = fingerprint_device("192.168.1.50")
    assert guess == "Unknown"
    assert ports == []

def test_fingerprint_device_apple():
    import lanhack.config as c
    c.devices = [{"ip":"192.168.1.50","mac":"00:1b:63:aa:bb:cc","vendor":"Apple","hostname":"","fingerprint":"","open_ports":""}]
    guess, ports = fingerprint_device("192.168.1.50")
    assert guess == "macOS/iOS"
