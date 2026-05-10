import unittest.mock, threading, time
import lanhack
from lanhack import arp_spoof_loop, arp_scan

@unittest.mock.patch("scapy.all.sendp")
def test_arp_spoof_block_loop(mock_sendp):
    ev = threading.Event()
    ev.set()
    t = threading.Thread(target=arp_spoof_loop, args=("192.168.1.50", "aa:bb:cc:dd:ee:ff", "192.168.1.1", ev, True), daemon=True)
    t.start()
    time.sleep(0.1)
    assert t.is_alive()
    ev.clear()
    t.join(timeout=2)
    assert not t.is_alive()

@unittest.mock.patch("scapy.all.sendp")
def test_arp_spoof_spy_loop(mock_sendp):
    ev = threading.Event()
    ev.set()
    t = threading.Thread(target=arp_spoof_loop, args=("192.168.1.50", "aa:bb:cc:dd:ee:ff", "192.168.1.1", ev, False), daemon=True)
    t.start()
    time.sleep(0.1)
    assert t.is_alive()
    ev.clear()
    t.join(timeout=2)
    assert not t.is_alive()

class FakeRecv:
    hwsrc = "aa:bb:cc:11:22:33"
    psrc = "192.168.1.50"

def fake_arping(*a, **kw):
    return ([(None, FakeRecv())], [])

@unittest.mock.patch("socket.gethostbyaddr")
def test_arp_scan(mock_gethost):
    mock_gethost.return_value = ("test-host.local", [], [])
    with unittest.mock.patch.object(lanhack.scapy, "arping", fake_arping):
        result = arp_scan("192.168.1.0/24")
        assert len(result) >= 1

def test_arp_scan_no_hostname():
    with unittest.mock.patch.object(lanhack.scapy, "arping", fake_arping):
        with unittest.mock.patch("socket.gethostbyaddr", side_effect=Exception("no reverse")):
            result = arp_scan("192.168.1.0/24")
            assert len(result) >= 1
            assert result[0]["hostname"] == ""
