import sys, subprocess, os

_REQUIREMENTS = ["scapy>=2.5.0", "textual>=1.0.0", "mitmproxy>=10.0.0"]

def _auto_install():
    missing = []
    try: import scapy.all
    except ImportError: missing.append("scapy")
    try: import textual
    except ImportError: missing.append("textual")
    if not missing: return
    pip = sys.executable + " -m pip install --user"
    for pkg in missing:
        req = [r for r in _REQUIREMENTS if r.startswith(pkg)][0]
        print(f"[*] Installing {req}...")
        subprocess.check_call(pip.split() + [req], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

_auto_install()

if os.geteuid() != 0:
    print("[!] Must run as root (sudo).")
    sys.exit(1)

from lanhack.config import *
from lanhack.network import vendor, fingerprint_device, wake_on_lan, detect_network, arp_scan, arp_spoof_loop, device_label, main_site, DEVICE_TYPES
from lanhack.monitor import sniff_sites
from lanhack.dns import _dns_server_run
from lanhack.harvester import harvester_proxy, _ensure_mitm_addon, _init_cred_file, HARVEST_JS
from lanhack.app import NetcutApp
