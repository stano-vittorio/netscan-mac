#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
NetScan - local network scanner for macOS (Python standard library only, nothing written to disk).
        / scanner di rete locale per macOS (solo libreria standard, nessuna installazione).

Uso:   python3 netscan.py
Poi si apre da solo il browser su http://127.0.0.1:8765

Non scrive NULLA su disco: nessun file, nessuna cache, nessuna cronologia
(nemmeno la preferenza del tema). Tutto vive solo in memoria: la lista viene
azzerata a ogni scansione manuale e lo script si chiude da solo, cancellando
tutto, quando chiudi la pagina del browser.

Cosa fa:
  - rileva da solo la rete attiva (interfaccia, IP, subnet, gateway), anche con VPN accesa
  - fa un ping sweep della subnet e legge la tabella ARP (IP + MAC)
  - recupera il nome con DNS inverso, mDNS/Bonjour e NetBIOS (in parallelo)
  - ricava il produttore dal MAC (database IEEE: MA-L, MA-M e MA-S, scaricato in memoria)
  - interfaccia web con tema chiaro/scuro, ricerca, ordinamento e IP cliccabili
"""
import csv
import io
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

__version__ = "1.0.0"

try:
    import resource
except ImportError:  # non dovrebbe succedere su macOS
    resource = None

PORT = 8765  # prima porta provata; se occupata prova le successive
OUI_URLS = [
    "https://standards-oui.ieee.org/oui/oui.csv",      # MA-L (24 bit)
    "https://standards-oui.ieee.org/oui28/mam.csv",    # MA-M (28 bit)
    "https://standards-oui.ieee.org/oui36/oui36.csv",  # MA-S (36 bit)
]

lock = threading.Lock()
state = {"scanning": False, "progress": 0, "net": None, "error": None, "last_scan": None,
         "interfaces": []}
devices = []  # elenco dell'ultima scansione, solo in memoria
oui = {}
oui_ready = threading.Event()
exit_timer = None
pages = {}  # schede del browser aperte: id -> ultimo contatto


# ---------------------------------------------------------------- utilita
def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def norm_mac(mac):
    return ":".join("%02X" % int(x, 16) for x in mac.split(":"))


def raise_fd_limit():
    """macOS ha un limite basso di file aperti: lo alziamo (solo per questo processo)."""
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


# ---------------------------------------------------------------- chiusura automatica
def cancel_exit():
    global exit_timer
    if exit_timer:
        exit_timer.cancel()
        exit_timer = None


def schedule_exit():
    """Pagina chiusa: dopo qualche secondo (se non e' un semplice reload) esce e libera tutto."""
    global exit_timer
    cancel_exit()

    def bye():
        print("\nPagina chiusa: NetScan terminato, nessun dato conservato.")
        os._exit(0)

    exit_timer = threading.Timer(1.5, bye)
    exit_timer.daemon = True
    exit_timer.start()


# ---------------------------------------------------------------- produttori (solo in memoria)
def _fetch_oui(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 netscan"})
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "ignore")
        rd = csv.reader(io.StringIO(text))
        next(rd, None)
        return {row[1].strip().upper(): row[2].strip() for row in rd if len(row) >= 3}
    except Exception:
        return {}


def load_oui():
    try:
        with ThreadPoolExecutor(len(OUI_URLS)) as ex:
            for part in ex.map(_fetch_oui, OUI_URLS):
                oui.update(part)
    finally:
        oui_ready.set()


def vendor(mac):
    if int(mac[:2], 16) & 2:  # bit "locally administered" = MAC casuale/privato
        return "MAC privato/casuale"
    h = mac.replace(":", "")
    for n in (9, 7, 6):  # prima i blocchi piu' specifici (MA-S, MA-M), poi MA-L
        v = oui.get(h[:n])
        if v:
            return v
    return ""


# ---------------------------------------------------------------- rete
def iface_info(iface):
    out = run(["ifconfig", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out)
    e = re.search(r"ether (\S+)", out)
    if not m or not e or "status: inactive" in out:
        return None
    ip = m.group(1)
    if ip.startswith("169.254."):  # link-local: niente DHCP, rete non utilizzabile
        return None
    mask = socket.inet_ntoa(struct.pack(">I", int(m.group(2), 16)))
    net = ipaddress.ip_network("%s/%s" % (ip, mask), strict=False)
    if net.prefixlen < 24:  # evita scansioni enormi: limita alla /24 dell'host
        net = ipaddress.ip_network("%s/24" % ip, strict=False)
    return {"iface": iface, "ip": ip, "net": net, "mac": norm_mac(e.group(1))}


def hardware_ports():
    """Nomi leggibili delle interfacce (Wi-Fi, Ethernet, Thunderbolt...) da networksetup."""
    names, port = {}, ""
    for line in run(["networksetup", "-listallhardwareports"]).splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            names[line.split(":", 1)[1].strip()] = port
    return names


def list_interfaces():
    """Interfacce di rete attive con un IPv4 valido, tra cui scegliere cosa scansionare."""
    names = hardware_ports()
    res = []
    for iface in run(["ifconfig", "-l"]).split():
        if not iface.startswith("en"):
            continue
        info = iface_info(iface)
        if info:
            res.append({"iface": iface, "name": names.get(iface, iface),
                        "ip": info["ip"], "net": str(info["net"])})
    return res


def detect_network(preferred=None):
    out = run(["route", "-n", "get", "default"])
    m = re.search(r"interface:\s*(\S+)", out)
    default_if = m.group(1) if m else None
    if preferred:  # interfaccia scelta dall'utente
        info = iface_info(preferred)
        if not info:
            raise RuntimeError("L'interfaccia %s non e' piu' attiva o non ha un indirizzo IP." % preferred)
        src = out if preferred == default_if else \
            run(["route", "-n", "get", "default", "-ifscope", preferred])
        g = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", src)
        info["gateway"] = g.group(1) if g else None
        info["bound"] = preferred != default_if  # solo se diversa dalla principale: ping legato all'interfaccia
        return info
    candidates = [m.group(1)] if m else []
    # se la rotta di default e' una VPN (utun...), ripiega sulle interfacce fisiche en*
    candidates += [i for i in run(["ifconfig", "-l"]).split()
                   if i.startswith("en") and i not in candidates]
    for i, iface in enumerate(candidates):
        info = iface_info(iface)
        if not info:
            continue
        src = out if (i == 0 and m) else run(["route", "-n", "get", "default", "-ifscope", iface])
        g = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", src)
        info["gateway"] = g.group(1) if g else None
        info["bound"] = False
        return info
    raise RuntimeError("Nessuna rete IPv4 attiva trovata (sei connesso a Wi-Fi/Ethernet?)")


def ping(ip, bound=None):
    cmd = ["ping"] + (["-b", bound] if bound else []) + ["-c", "1", "-t", "1", "-q", ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    m = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
    return float(m.group(1)) if m else 0.0


def arp_table(iface, net):
    res = {}
    for line in run(["arp", "-an"]).splitlines():
        m = re.match(r"\? \((\S+)\) at (\S+) on (\S+)", line)
        if not m or m.group(3) != iface:
            continue
        ip, mac = m.group(1), m.group(2)
        if mac.count(":") != 5:  # "(incomplete)" = nessuna risposta
            continue
        mac = norm_mac(mac)
        if mac == "FF:FF:FF:FF:FF:FF" or ipaddress.ip_address(ip) not in net:
            continue
        if ip == str(net.broadcast_address):
            continue
        res[ip] = mac
    return res


# ---------------------------------------------------------------- nomi
def name_dns(ip):
    try:
        n = socket.gethostbyaddr(ip)[0].rstrip(".")
        return n if n and n != ip else None
    except Exception:
        return None


def _read_name(data, pos):
    labels, jumped, end, hops = [], False, pos, 0
    while True:
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            hops += 1
            if hops > 20:
                raise ValueError("loop nei puntatori DNS")
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            continue
        labels.append(data[pos + 1:pos + 1 + ln].decode("utf-8", "ignore"))
        pos += 1 + ln
    if not jumped:
        end = pos
    return ".".join(labels), end


def _parse_mdns(data):
    qd, an = struct.unpack(">HH", data[4:8])
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(data, pos)
        pos += 4
    for _ in range(an):
        _, pos = _read_name(data, pos)
        typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        if typ == 12:  # PTR
            n, _ = _read_name(data, pos + 10)
            return re.sub(r"\.local\.?$", "", n) or None
        pos += 10 + rdlen
    return None


def name_mdns(ip):
    """Query mDNS PTR unicast direttamente al dispositivo (porta 5353)."""
    q = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in reversed(ip.split(".")):
        q += bytes([len(part)]) + part.encode()
    q += b"\x07in-addr\x04arpa\x00\x00\x0c\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.2)
    try:
        s.sendto(q, (ip, 5353))
        data, _ = s.recvfrom(2048)
        return _parse_mdns(data)
    except Exception:
        return None
    finally:
        s.close()


def _parse_nbstat(data):
    count = data[56]
    for i in range(count):
        off = 57 + i * 18
        nm = data[off:off + 15].decode("ascii", "ignore").strip()
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16:off + 18])[0]
        if suffix == 0 and not flags & 0x8000 and nm:  # nome host, non di gruppo
            return nm
    return None


def name_netbios(ip):
    q = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0)
    q += b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00\x00\x21\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.sendto(q, (ip, 137))
        data, _ = s.recvfrom(1024)
        return _parse_nbstat(data)
    except Exception:
        return None
    finally:
        s.close()


def resolve_name(ip):
    """Lancia DNS, mDNS e NetBIOS insieme; vince il primo (in ordine di priorita') che risponde."""
    fns = ((name_dns, "DNS"), (name_mdns, "mDNS"), (name_netbios, "NetBIOS"))
    ex = ThreadPoolExecutor(len(fns))
    try:
        futs = [(ex.submit(fn, ip), src) for fn, src in fns]
        for fut, src in futs:
            n = fut.result()
            if n:
                return n, src
    finally:
        ex.shutdown(wait=False)
    return None, None


# ---------------------------------------------------------------- scansione
def scan(keep=False, iface=None):
    """keep=True (auto-refresh): la lista resta visibile finche' non e' pronta quella nuova."""
    global devices
    with lock:
        if state["scanning"]:
            return
        state.update(scanning=True, progress=0, error=None)
        prev = {d["mac"]: (d["name"], d["name_src"]) for d in devices} if keep else {}
        if not keep:
            devices = []  # la lista precedente viene eliminata
    try:
        state["interfaces"] = list_interfaces()
        info = detect_network(iface)
        net = info["net"]
        hosts = [str(h) for h in net.hosts()]
        state["net"] = "%s  (%s, gateway %s)" % (net, info["iface"], info["gateway"])

        done, pings = 0, {}
        bound = info["iface"] if info["bound"] else None
        with ThreadPoolExecutor(100) as ex:
            for h, ms in zip(hosts, ex.map(lambda h: ping(h, bound), hosts)):
                pings[h] = ms
                done += 1
                state["progress"] = int(done / max(len(hosts), 1) * 60)

        found = arp_table(info["iface"], net)
        found[info["ip"]] = info["mac"]

        oui_ready.wait(timeout=20)  # il database dei produttori arriva dal web all'avvio
        result = []
        for ip, mac in found.items():
            name, src = prev.get(mac, ("", ""))
            result.append({
                "ip": ip, "mac": mac, "vendor": vendor(mac),
                "name": name, "name_src": src, "ping": pings.get(ip),
                "is_self": ip == info["ip"], "is_gateway": ip == info["gateway"],
            })
        with lock:
            devices = result  # mostra subito IP/MAC/produttore, i nomi arrivano dopo

        with ThreadPoolExecutor(32) as ex:
            futs = [(d, ex.submit(resolve_name, d["ip"])) for d in result]
            for i, (d, fut) in enumerate(futs):
                name, src = fut.result()
                if not name and d["is_self"]:
                    name, src = socket.gethostname(), "locale"
                if name:
                    with lock:
                        d["name"], d["name_src"] = name, src or ""
                state["progress"] = 60 + int((i + 1) / len(futs) * 40)
        state["last_scan"] = int(time.time())
    except Exception as e:
        state["error"] = str(e)
    finally:
        state.update(scanning=False, progress=100)


# ---------------------------------------------------------------- web
PAGE = r"""<!doctype html>
<html lang="it" data-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScan</title>
<script>document.documentElement.dataset.theme=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'</script>
<style>
:root{--bg:#f6f7f9;--fg:#1c1e21;--card:#fff;--mut:#6b7280;--bd:#e5e7eb;--ac:#2563eb;--acfg:#fff;--hv:#f1f5f9;--errbg:#fee2e2;--errfg:#991b1b;--ok:#16a34a;--bad:#dc2626;color-scheme:light}
:root[data-theme="dark"]{--bg:#14161a;--fg:#e6e8eb;--card:#1c1f25;--mut:#9aa1ac;--bd:#2c313a;--ac:#60a5fa;--acfg:#0b1220;--hv:#242932;--errbg:#3b1d1d;--errfg:#fca5a5;--ok:#4ade80;--bad:#f87171;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px -apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif;transition:background .2s,color .2s}
header{padding:18px 24px;display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
h1{font-size:20px;margin:0}
.sub{color:var(--mut);font-size:13px;margin-top:2px}
.tools{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
button{background:var(--ac);color:var(--acfg);border:0;border-radius:8px;padding:8px 14px;font-size:14px;cursor:pointer}
button:disabled{opacity:.6;cursor:default}
select{padding:8px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);font-size:14px;max-width:280px}
select:disabled{opacity:.6}
input[type=search]{padding:8px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);width:200px}
label{color:var(--mut);font-size:13px}
.theme{display:flex;align-items:center;gap:8px;position:relative;cursor:pointer;user-select:none}
.theme input{position:absolute;opacity:0;width:0;height:0}
.sl{position:relative;width:42px;height:24px;border-radius:99px;background:var(--bd);transition:background .2s}
.sl::after{content:"";position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.35);transition:transform .2s}
.theme input:checked+.sl{background:var(--ac)}
.theme input:checked+.sl::after{transform:translateX(18px)}
.theme input:focus-visible+.sl{outline:2px solid var(--ac);outline-offset:2px}
.bar{height:3px;background:var(--bd)}.bar div{height:100%;background:var(--ac);transition:width .3s}
main{padding:0 24px 24px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--bd);white-space:nowrap}
th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;cursor:pointer;user-select:none}
th:hover{color:var(--fg)}
th.asc::after{content:" \25B2"}th.desc::after{content:" \25BC"}
tbody tr:hover td{background:var(--hv)}
tr:last-child td{border-bottom:0}
td.empty{text-align:center;color:var(--mut);padding:28px}
a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline}
.pd{display:inline-block;width:10px;height:10px;border-radius:50%;vertical-align:middle}
.pd.ok{background:var(--ok)}.pd.bad{background:var(--bad)}
.ms{color:var(--mut);font-size:11px;margin-left:6px}
.legend{color:var(--mut);font-size:12px;margin-top:10px}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px}
.tag{font-size:11px;padding:1px 7px;border-radius:99px;border:1px solid var(--bd);color:var(--mut);margin-left:6px}
.src{color:var(--mut);font-size:11px;margin-left:6px}
.err{background:var(--errbg);color:var(--errfg);padding:10px 14px;border-radius:8px;margin:0 24px 12px}
</style></head><body>
<header>
 <div><h1>NetScan</h1><div class="sub" id="sub">&nbsp;</div></div>
 <div class="tools">
  <select id="ifc" title="Rete da scansionare"><option value="">Rete: automatica</option></select>
  <input type="search" id="q" placeholder="Cerca IP, MAC, nome...">
  <label><input type="checkbox" id="auto"> Auto-refresh (60 s)</label>
  <button id="go">Scansiona</button>
  <label class="theme" title="Tema chiaro / scuro">
   <span aria-hidden="true">&#9728;</span>
   <input type="checkbox" id="theme" aria-label="Tema scuro">
   <i class="sl"></i>
   <span aria-hidden="true">&#9790;</span>
  </label>
 </div>
</header>
<div class="bar"><div id="pb" style="width:0"></div></div>
<div id="err"></div>
<main><div class="card"><table>
<thead><tr>
 <th data-k="ping">Ping</th><th data-k="ip">Indirizzo IP</th><th data-k="mac">MAC</th>
 <th data-k="vendor">Produttore</th><th data-k="name">Nome</th>
</tr></thead><tbody id="tb"></tbody></table></div>
<div class="legend"><span class="pd ok"></span> risponde al ping &nbsp;&nbsp; <span class="pd bad"></span> non risponde al ping (il dispositivo e' comunque presente in rete: firewall o standby)</div></main>
<script>
const pid=Math.random().toString(36).slice(2);
let data=null,sortK='ip',sortDir=1,manual=false,selIface='',ifcSig='';
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ipn=ip=>ip.split('.').reduce((a,b)=>a*256+(+b),0);
function pingCell(d){
  if(d.ping==null)return '<span class="pd bad" title="Non risponde al ping (presente in rete: firewall o standby)"></span>';
  return '<span class="pd ok" title="Risponde al ping"></span><span class="ms">'+(d.ping<1?'<1':Math.round(d.ping))+' ms</span>';
}
function val(d,k){
  if(k==='ping')return d.ping==null?1e9:d.ping;
  if(k==='ip')return ipn(d.ip);
  return (d[k]||'').toString().toLowerCase();
}
function ago(t){
  const s=Math.floor(Date.now()/1000)-t;
  if(s<90)return 'adesso';
  if(s<3600)return Math.floor(s/60)+' min fa';
  return Math.floor(s/3600)+' h fa';
}
function startScan(keep){
  const p=[];if(keep)p.push('keep=1');if(selIface)p.push('iface='+encodeURIComponent(selIface));
  return fetch('/api/scan'+(p.length?'?'+p.join('&'):''),{method:'POST'});
}
function renderIfaces(st){
  const list=st.interfaces||[],sig=JSON.stringify(list);
  if(sig!==ifcSig){
    ifcSig=sig;
    if(selIface&&!list.some(x=>x.iface===selIface))selIface='';
    $('ifc').innerHTML='<option value="">Rete: automatica</option>'+list.map(x=>
      '<option value="'+esc(x.iface)+'">'+esc(x.name)+' ('+esc(x.iface)+') · '+esc(x.net)+'</option>').join('');
    $('ifc').value=selIface;
  }
  $('ifc').disabled=st.scanning;
}
function render(){
  if(!data)return;
  const st=data.state,q=$('q').value.toLowerCase();
  renderIfaces(st);
  const list=data.devices.filter(d=>(d.ip+' '+d.mac+' '+d.name+' '+(d.vendor||'')).toLowerCase().includes(q));
  list.sort((a,b)=>{const x=val(a,sortK),y=val(b,sortK);return (x<y?-1:x>y?1:0)*sortDir});
  $('tb').innerHTML=list.length?list.map(d=>`<tr>
   <td>${pingCell(d)}</td>
   <td class="mono"><a href="http://${esc(d.ip)}" target="_blank" rel="noopener" title="Apri http://${esc(d.ip)}">${esc(d.ip)}</a></td>
   <td class="mono">${esc(d.mac)}</td>
   <td>${esc(d.vendor)}</td>
   <td>${esc(d.name)||'<span class="src">-</span>'}
    ${d.name_src?'<span class="src">'+esc(d.name_src)+'</span>':''}
    ${d.is_self?'<span class="tag">questo Mac</span>':''}${d.is_gateway?'<span class="tag">gateway</span>':''}</td></tr>`).join('')
   :'<tr><td class="empty" colspan="5">'+(st.scanning?'Scansione in corso...':data.devices.length?'Nessun risultato per la ricerca':'Nessun dispositivo trovato')+'</td></tr>';
  document.querySelectorAll('th').forEach(th=>{
    th.classList.remove('asc','desc');
    if(th.dataset.k===sortK)th.classList.add(sortDir>0?'asc':'desc');
  });
  $('sub').textContent=(st.net||'Rilevo la rete...')+' · '+data.devices.length+' dispositivi'+
    (st.scanning?' · scansione '+st.progress+'%':(st.last_scan?' · ultima scansione '+ago(st.last_scan):''));
  $('pb').style.width=(st.scanning?st.progress:0)+'%';
  $('go').disabled=st.scanning;$('go').textContent=st.scanning?'Scansione...':'Scansiona';
  $('err').innerHTML=st.error?'<div class="err">'+esc(st.error)+'</div>':'';
}
async function load(){
  try{data=await (await fetch('/api/devices?id='+pid)).json();render();}catch(e){}
  setTimeout(load,data&&data.state.scanning?800:3000);
}
$('go').onclick=()=>startScan(false).then(load);
$('ifc').onchange=e=>{selIface=e.target.value;startScan(false).then(load);};
$('q').oninput=render;
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{
  const k=th.dataset.k;sortDir=(sortK===k)?-sortDir:1;sortK=k;render();});
setInterval(()=>{if($('auto').checked&&!(data&&data.state.scanning))startScan(true);},60000);
/* tema: solo in memoria (nessun salvataggio), parte da quello del sistema */
const mq=matchMedia('(prefers-color-scheme: dark)');
function setTheme(dark){document.documentElement.dataset.theme=dark?'dark':'light';$('theme').checked=dark;}
$('theme').onchange=e=>{manual=true;setTheme(e.target.checked);};
mq.onchange=e=>{if(!manual)setTheme(e.matches);};
setTheme(mq.matches);
window.addEventListener('pagehide',()=>navigator.sendBeacon('/api/bye?id='+pid));
load();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _allowed(self):
        """Accetta solo richieste dalla pagina locale (protegge da siti esterni e DNS rebinding)."""
        ok_host = ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT)
        if self.headers.get("Host", "") not in ok_host:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in ["http://" + h for h in ok_host]

    def _send(self, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if not self._allowed():
            return self.send_error(403)
        path, _, query = self.path.partition("?")
        if path == "/api/devices":
            cancel_exit()
            pid = parse_qs(query).get("id", [""])[0][:40]
            with lock:
                if pid:
                    pages[pid] = time.time()
                out = {"state": dict(state), "devices": [dict(d) for d in devices]}
            self._send(json.dumps(out))
        elif path == "/":
            self._send(PAGE, "text/html")
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._allowed():
            return self.send_error(403)
        path, _, query = self.path.partition("?")
        if path == "/api/scan":
            qs = parse_qs(query)
            iface = qs.get("iface", [""])[0]
            if not re.fullmatch(r"en\d+", iface):
                iface = None
            threading.Thread(target=scan, kwargs={"keep": "keep=1" in query, "iface": iface},
                             daemon=True).start()
            self._send("{}")
        elif path == "/api/bye":
            pid = parse_qs(query).get("id", [""])[0][:40]
            with lock:
                pages.pop(pid, None)
                for k in [k for k, t in pages.items() if time.time() - t > 90]:
                    del pages[k]  # schede sparite senza avvisare (es. crash del browser)
                last = not pages
            if last:  # chiusa l'ultima scheda: si spegne subito
                schedule_exit()
            self._send("{}")
        else:
            self.send_error(404)


def main():
    global PORT
    srv = None
    for port in range(PORT, PORT + 11):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            PORT = port
            break
        except OSError:
            continue
    if srv is None:
        print("Nessuna porta libera tra %d e %d." % (PORT, PORT + 10))
        return
    raise_fd_limit()
    threading.Thread(target=load_oui, daemon=True).start()
    threading.Thread(target=scan, daemon=True).start()
    url = "http://127.0.0.1:%d" % PORT
    print("NetScan attivo su %s  (Ctrl+C per uscire)" % url)
    webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nChiuso.")


if __name__ == "__main__":
    main()
