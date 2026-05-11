import sys, os, unittest.mock, pytest, types

textual_pkg = types.ModuleType("textual")
textual_pkg.__path__ = ["/fake/textual"]
textual_pkg.__name__ = "textual"
textual_pkg.app = unittest.mock.MagicMock()
textual_pkg.containers = unittest.mock.MagicMock()
textual_pkg.widgets = unittest.mock.MagicMock()
textual_pkg.screen = unittest.mock.MagicMock()
textual_pkg.binding = unittest.mock.MagicMock()
textual_pkg.reactive = unittest.mock.MagicMock()
textual_pkg.events = unittest.mock.MagicMock()
textual_pkg.widget = unittest.mock.MagicMock()
textual_pkg.keys = unittest.mock.MagicMock()
textual_pkg.css = unittest.mock.MagicMock()
textual_pkg.content = unittest.mock.MagicMock()
textual_pkg.geometry = unittest.mock.MagicMock()
textual_pkg._node_list = unittest.mock.MagicMock()
textual_pkg._timer = unittest.mock.MagicMock()
textual_pkg.message = unittest.mock.MagicMock()
textual_pkg._types = unittest.mock.MagicMock()
textual_pkg._wait = unittest.mock.MagicMock()
textual_pkg._context = unittest.mock.MagicMock()
textual_pkg._callback = unittest.mock.MagicMock()
textual_pkg._arrange = unittest.mock.MagicMock()
textual_pkg._dom_helpers = unittest.mock.MagicMock()
textual_pkg._factory = unittest.mock.MagicMock()
textual_pkg._warn = unittest.mock.MagicMock()
textual_pkg._path = unittest.mock.MagicMock()
textual_pkg._xterm_parser = unittest.mock.MagicMock()
textual_pkg._cells = unittest.mock.MagicMock()
textual_pkg._layouts = unittest.mock.MagicMock()
textual_pkg.Align = unittest.mock.MagicMock()
textual_pkg.Rule = unittest.mock.MagicMock()
textual_pkg.Columns = unittest.mock.MagicMock()

sys.modules["textual"] = textual_pkg
sys.modules["textual.app"] = textual_pkg.app
sys.modules["textual.containers"] = textual_pkg.containers
sys.modules["textual.widgets"] = textual_pkg.widgets
sys.modules["textual.screen"] = textual_pkg.screen
sys.modules["textual.binding"] = textual_pkg.binding
sys.modules["textual.reactive"] = textual_pkg.reactive
sys.modules["textual.events"] = textual_pkg.events
sys.modules["textual.widget"] = textual_pkg.widget
sys.modules["textual.keys"] = textual_pkg.keys
sys.modules["textual.css"] = textual_pkg.css
sys.modules["textual.content"] = textual_pkg.content
sys.modules["textual.geometry"] = textual_pkg.geometry
sys.modules["textual._node_list"] = textual_pkg._node_list
sys.modules["textual._timer"] = textual_pkg._timer
sys.modules["textual.message"] = textual_pkg.message
sys.modules["textual._types"] = textual_pkg._types
sys.modules["textual._wait"] = textual_pkg._wait
sys.modules["textual._context"] = textual_pkg._context
sys.modules["textual._callback"] = textual_pkg._callback
sys.modules["textual._arrange"] = textual_pkg._arrange
sys.modules["textual._dom_helpers"] = textual_pkg._dom_helpers
sys.modules["textual._factory"] = textual_pkg._factory
sys.modules["textual._warn"] = textual_pkg._warn
sys.modules["textual._path"] = textual_pkg._path
sys.modules["textual._xterm_parser"] = textual_pkg._xterm_parser
sys.modules["textual._cells"] = textual_pkg._cells
sys.modules["textual._layouts"] = textual_pkg._layouts
sys.modules["textual.widgets._tabbed_content"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._button"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._data_table"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._input"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._rich_log"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._tabs"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._content_switcher"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._static"] = unittest.mock.MagicMock()
sys.modules["textual.widgets._toast"] = unittest.mock.MagicMock()
sys.modules["textual.containers"] = unittest.mock.MagicMock()
sys.modules["textual.scroll_view"] = unittest.mock.MagicMock()
sys.modules["textual._xterm_parser"] = unittest.mock.MagicMock()

unittest.mock.patch.object(os, "geteuid", return_value=0).start()

scapy_mock = unittest.mock.MagicMock()
scapy_mock.conf = unittest.mock.MagicMock()
scapy_mock.conf.route = unittest.mock.MagicMock()
scapy_mock.conf.route.routes = []

class FakeIP:
    src = "192.168.1.10"
    dst = "8.8.8.8"

class FakeDNS:
    qr = 0
    def __getitem__(self, k): return self

class FakeDNSQR:
    qname = b"example.com"

class FakeTCP:
    dport = 443
    sport = 12345
    flags = 0x12

class FakeRaw:
    load = b""

class FakeEther:
    def __init__(self, dst=""): self.dst = dst
    def __truediv__(self, other): return self

class FakeARP:
    op = 2
    pdst = ""
    psrc = ""
    hwdst = ""
    def __init__(self, **kw): self.__dict__.update(kw)

scapy_mock.IP.return_value = FakeIP()
scapy_mock.DNS = FakeDNS
scapy_mock.DNSQR = FakeDNSQR
scapy_mock.TCP = FakeTCP
scapy_mock.Raw = FakeRaw
scapy_mock.Ether = FakeEther
scapy_mock.ARP = lambda **kw: FakeARP(**kw)
scapy_mock.get_if_hwaddr.return_value = "aa:bb:cc:dd:ee:ff"
scapy_mock.get_if_addr.return_value = "192.168.1.100"
scapy_mock.utils.atol.return_value = 0xC0A80100
scapy_mock.utils.ltoa.return_value = "192.168.1.0"

class FakeAnswer:
    hwsrc = "aa:bb:cc:11:22:33"
    psrc = "192.168.1.50"

def fake_arping(*args, **kw):
    return ([(None, FakeAnswer())], [])

scapy_mock.arping = fake_arping

sys.modules["scapy"] = scapy_mock
sys.modules["scapy.all"] = scapy_mock
sys.modules["scapy.utils"] = scapy_mock.utils

sys.modules["mitmproxy"] = unittest.mock.MagicMock()
sys.modules["mitmproxy.http"] = unittest.mock.MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import lanhack.config as C

@pytest.fixture(autouse=True)
def reset_globals():
    C.captured_sites.clear()
    C.devices.clear()
    C.blocked_ips.clear()
    C.spoof_threads.clear()
    C.spy_threads.clear()
    C.custom_blocks.clear()
    C.harvested_creds.clear()
    C.dns_blocklist.clear()
    C.bandwidth_data.clear()
    C.domain_hits.clear()
    C.dns_stop = False
    C.my_ip = "192.168.1.100"
    C.gateway_ip = "192.168.1.1"
    C.iface = "eth0"
    C.netmask = "192.168.1.0/24"

@pytest.fixture
def sample_devices():
    return [
        {"ip":"192.168.1.50","mac":"aa:bb:cc:00:11:22","vendor":"Apple","hostname":"iphone","fingerprint":"","open_ports":""},
        {"ip":"192.168.1.60","mac":"dd:ee:ff:33:44:55","vendor":"Samsung","hostname":"","fingerprint":"","open_ports":""},
    ]
