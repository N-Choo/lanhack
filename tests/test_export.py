import json, csv, io, os
from lanhack import device_label, main_site
from lanhack import config as C

SAMPLE_CAPTURES = {
    "192.168.1.50": [
        ("14:30:00", "youtube.com", "dns", "192.168.1.50", "8.8.8.8"),
        ("14:30:05", "github.com", "dns", "192.168.1.50", "8.8.8.8"),
    ],
    "192.168.1.60": [
        ("14:31:00", "discord.com", "dns", "192.168.1.60", "1.1.1.1"),
    ],
}

SAMPLE_CREDS = [
    ("PWD", "pw=secret123", "14:32:00"),
    ("GET", "user=admin&pass=hunter2", "14:32:30"),
]

def test_csv_format():
    C.captured_sites.clear()
    for ip, entries in SAMPLE_CAPTURES.items():
        C.captured_sites[ip] = entries
    output = io.StringIO()
    rows = []
    for ip in C.captured_sites:
        for ts, site, stype, src, dst in C.captured_sites[ip]:
            rows.append({"Time":ts,"Device":device_label(ip),"IP":ip,"Type":stype,"Site":site})
    w = csv.DictWriter(output, fieldnames=["Time","Device","IP","Type","Site"])
    w.writeheader()
    w.writerows(rows)
    text = output.getvalue()
    assert "Time,Device,IP,Type,Site" in text
    assert "youtube.com" in text
    assert "discord.com" in text
    assert "192.168.1.50" in text

def test_json_format():
    data = {"captures": [], "total": 0, "harvested_http": SAMPLE_CREDS}
    for ip, entries in SAMPLE_CAPTURES.items():
        for ts, site, stype, src, dst in entries:
            data["captures"].append({"Time":ts,"Device":device_label(ip),"IP":ip,"Type":stype,"Site":site})
    data["total"] = len(data["captures"])
    text = json.dumps(data, indent=2)
    assert '"total": 3' in text
    assert '"Site": "youtube.com"' in text
    assert '"harvested_http"' in text
    assert 'secret123' in text

def test_empty_export():
    C.captured_sites.clear()
    rows = []
    for ip in C.captured_sites:
        for ts, site, stype, src, dst in C.captured_sites[ip]:
            rows.append({"Time":ts,"Device":device_label(ip),"IP":ip,"Type":stype,"Site":site})
    assert len(rows) == 0

def test_cdn_mapping_in_export():
    site = "rr2.sn-uxaxovg-vnaee.googlevideo.com"
    mapped = main_site(site)
    assert mapped == "youtube.com"

def test_export_credential_harvest():
    harvester_output = "\n".join([c[1] for c in SAMPLE_CREDS])
    assert "secret123" in harvester_output
    assert "hunter2" in harvester_output
