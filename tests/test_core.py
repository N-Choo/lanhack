from lanhack.network import vendor, device_label, main_site, wake_on_lan
from lanhack.config import OUI_DB, CDN_MAP
from lanhack import config as C

def test_vendor_known():
    assert vendor("b0:a7:b9:00:00:00") == "TP-Link"
    assert vendor("c8:5a:cf:12:34:56") == "HP Inc."
    assert vendor("70:08:10:ab:cd:ef") == "Intel"

def test_vendor_unknown():
    assert vendor("00:00:00:00:00:00") == "Unknown"
    assert vendor("ff:ff:ff:ff:ff:ff") == "Unknown"

def test_vendor_case_insensitive():
    assert vendor("B0:A7:B9:00:00:00") == "TP-Link"

def test_device_label_known(sample_devices):
    C.devices = sample_devices
    label = device_label("192.168.1.50")
    assert "iphone" in label
    assert "192.168.1.50" in label

def test_device_label_unknown_ip():
    C.devices = []
    assert device_label("10.0.0.1") == "10.0.0.1"

def test_device_label_known_vendor(sample_devices):
    C.devices = sample_devices
    label = device_label("192.168.1.60")
    assert "Samsung" in label
    assert "192.168.1.60" in label

def test_main_site_youtube():
    for url in ["googlevideo.com", "rr2.sn-uxaxovg-vnaee.googlevideo.com", "ytimg.com", "ggpht.com"]:
        assert main_site(url) == "youtube.com", f"Failed for {url}"

def test_main_site_pornhub():
    for url in ["phncdn.com", "ss.phncdn.com.sds.rncdn7.com"]:
        assert main_site(url) == "pornhub.com", f"Failed for {url}"

def test_main_site_unchanged():
    assert main_site("google.com") == "google.com"
    assert main_site("github.com") == "github.com"

def test_cdn_map_coverage():
    assert len(CDN_MAP) >= 5
    for cdn, target in CDN_MAP.items():
        assert isinstance(cdn, str)
        assert isinstance(target, str)

def test_oui_db_coverage():
    assert len(OUI_DB) > 20
    for prefix, name in OUI_DB.items():
        assert len(prefix) == 8
        assert isinstance(name, str)

def test_wake_on_lan_packet():
    result = wake_on_lan("aa:bb:cc:dd:ee:ff")
    assert result == True

def test_wake_on_lan_mac_formats():
    assert wake_on_lan("aa:bb:cc:dd:ee:ff") == True
    assert wake_on_lan("aa-bb-cc-dd-ee-ff") == True
