#!/usr/bin/env python3
"""
Escáner simple de la red WiFi local — un solo archivo (backend + web), solo librería estándar.

Uso:
    python3 app.py            # abre http://localhost:8000
    python3 app.py --port 9000

Guarda nombres, historial y ajustes en devices_db.json (junto a este archivo).

Úsalo solo en redes que sean tuyas o en las que tengas permiso.
"""
import argparse
import ipaddress
import json
import re
import socket
import statistics
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).parent
VENDOR_CACHE_FILE = BASE / "vendor_cache.json"

# Puertos comunes que ayudan a adivinar el tipo de dispositivo
PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB (Windows/NAS)",
    548: "AFP (Mac)",
    554: "RTSP (cámara)",
    631: "IPP (impresora)",
    5000: "UPnP/Synology",
    7000: "AirPlay",
    8008: "Chromecast",
    8009: "Chromecast",
    8080: "HTTP-alt",
    9100: "Impresora RAW",
    62078: "iPhone/iPad (lockdown)",
}

_vendor_lock = threading.Lock()
try:
    VENDOR_CACHE = json.loads(VENDOR_CACHE_FILE.read_text())
except Exception:
    VENDOR_CACHE = {}

scan_state = {"running": False, "progress": 0, "total": 0, "result": None, "error": None,
              "next_scan": None}

# ---------------------------------------------------------------- base de datos local
DB_FILE = BASE / "devices_db.json"
MAX_EVENTS = 3000
_db_lock = threading.RLock()
try:
    DB = json.loads(DB_FILE.read_text())
except Exception:
    DB = {}
DB.setdefault("settings", {"interval_min": 0, "mac_notify": True})
DB.setdefault("devices", {})
DB.setdefault("events", [])


def save_db():
    with _db_lock:
        tmp = DB_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(DB, indent=1, ensure_ascii=False))
        tmp.replace(DB_FILE)


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def dev_key(d):
    return d["mac"] or f"ip:{d['ip']}"


def display_name(rec, d=None):
    d = d or {}
    return rec.get("alias") or d.get("hostname") or rec.get("hostname") or \
        f"{d.get('type') or rec.get('type') or 'Dispositivo'} ({d.get('ip') or rec.get('last_ip')})"


def mac_notify(msg):
    """Notificación nativa de macOS (funciona aunque la web esté cerrada)."""
    if not DB["settings"].get("mac_notify", True):
        return
    sh(["osascript", "-e", "on run argv", "-e",
        'display notification (item 1 of argv) with title "Escáner WiFi" sound name "Glass"',
        "-e", "end run", msg], timeout=5)


def update_db(devices):
    """Compara el escaneo con lo conocido: nuevos, reconectados y desconectados."""
    t = now()
    with _db_lock:
        known = DB["devices"]
        baseline = not known          # primer escaneo: no avisar de todo
        seen = set()
        new_names = []
        for d in devices:
            k = dev_key(d)
            seen.add(k)
            d["key"] = k
            rec = known.get(k)
            if rec is None:
                rec = known[k] = {"first_seen": t, "online": False}
                if not baseline:
                    d["is_new"] = True
                    new_names.append(display_name(rec, d))
                DB["events"].append({"t": t, "key": k, "kind": "nuevo" if not baseline else "inicial",
                                     "ip": d["ip"], "name": display_name(rec, d)})
            elif not rec.get("online"):
                DB["events"].append({"t": t, "key": k, "kind": "conectado",
                                     "ip": d["ip"], "name": display_name(rec, d)})
            rec.update(online=True, last_seen=t, last_ip=d["ip"], type=d["type"],
                       vendor=d.get("vendor") or rec.get("vendor"),
                       hostname=d.get("hostname") or rec.get("hostname"))
            d["is_new"] = d.get("is_new", False) or rec.get("unacknowledged", False)
            if d.get("is_new"):
                rec["unacknowledged"] = True
        for k, rec in known.items():
            if rec.get("online") and k not in seen:
                rec["online"] = False
                DB["events"].append({"t": t, "key": k, "kind": "desconectado",
                                     "ip": rec.get("last_ip"), "name": display_name(rec)})
        DB["events"] = DB["events"][-MAX_EVENTS:]
        save_db()
    if new_names:
        mac_notify(("Nuevo dispositivo: " if len(new_names) == 1 else "Nuevos dispositivos: ")
                   + ", ".join(new_names))
    return new_names


def full_result():
    """Último escaneo + datos guardados (nombres, desconectados, historial)."""
    r = scan_state["result"]
    with _db_lock:
        known = DB["devices"]
        out = dict(r) if r else {}
        if r:
            devs = []
            for d in r["devices"]:
                d = dict(d)
                rec = known.get(d.get("key"), {})
                d["alias"] = rec.get("alias")
                d["first_seen"] = rec.get("first_seen")
                d["is_new"] = rec.get("unacknowledged", False)
                devs.append(d)
            out["devices"] = devs
        out["offline"] = [dict(rec, key=k) for k, rec in known.items() if not rec.get("online")]
        out["offline"].sort(key=lambda x: x.get("last_seen") or "", reverse=True)
        names = {k: display_name(rec) for k, rec in known.items()}
        out["events"] = [dict(e, name=names.get(e["key"], e["name"])) for e in DB["events"][-300:]][::-1]
        out["settings"] = DB["settings"]
    return out


def start_scan():
    if scan_state["running"]:
        return False
    scan_state.update(running=True, progress=0, total=0, error=None)
    threading.Thread(target=scan, daemon=True).start()
    return True


def auto_scan_loop():
    """Lanza escaneos periódicos según settings.interval_min (0 = apagado)."""
    last = 0
    while True:
        mins = DB["settings"].get("interval_min") or 0
        if mins and not scan_state["running"]:
            if last == 0:
                last = time.time()
            due = last + mins * 60
            scan_state["next_scan"] = time.strftime("%H:%M:%S", time.localtime(due))
            if time.time() >= due:
                start_scan()
                last = time.time()
        elif not mins:
            last = 0
            scan_state["next_scan"] = None
        time.sleep(2)


# ---------------------------------------------------------------- red local
def sh(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def local_network():
    out = sh(["route", "-n", "get", "default"])
    iface = re.search(r"interface:\s*(\S+)", out)
    gw = re.search(r"gateway:\s*(\S+)", out)
    iface = iface.group(1) if iface else "en0"
    gw = gw.group(1) if gw else None
    ifc = sh(["ifconfig", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", ifc)
    if not m:
        raise RuntimeError(f"No se encontró IP en la interfaz {iface}")
    ip = m.group(1)
    mask = str(ipaddress.IPv4Address(int(m.group(2), 16)))
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    mac = re.search(r"ether ([0-9a-f:]{17})", ifc)
    return {"iface": iface, "ip": ip, "gateway": gw, "network": str(net),
            "mac": mac.group(1) if mac else None}


def wifi_info():
    """Señal (RSSI) y ruido de *tu* conexión WiFi en macOS."""
    out = sh(["system_profiler", "SPAirPortDataType"], timeout=20)
    info = {}
    block = out.split("Current Network Information:")
    if len(block) > 1:
        cur = block[1]
        name = re.search(r"^\s+(.+):\s*$", cur, re.M)
        if name:
            info["ssid"] = name.group(1).strip()
        for key, rx in {"rssi": r"Signal / Noise:\s*(-?\d+) dBm / (-?\d+) dBm",
                        "channel": r"Channel:\s*(.+)",
                        "phy": r"PHY Mode:\s*(.+)",
                        "rate": r"Transmit Rate:\s*(\d+)"}.items():
            mm = re.search(rx, cur)
            if not mm:
                continue
            if key == "rssi":
                info["rssi"], info["noise"] = int(mm.group(1)), int(mm.group(2))
            else:
                info[key] = mm.group(1).strip()
    if "rssi" in info:
        info["router_distance"] = rssi_to_distance(info["rssi"], info.get("channel", ""))
    return info


def rssi_to_distance(rssi, channel):
    """Modelo log-distance path loss (interior). Muy aproximado."""
    five_ghz = "5GHz" in channel or "6GHz" in channel
    ref = -45 if five_ghz else -40      # RSSI esperado a 1 m
    n = 3.0                             # exponente típico interior con paredes
    d = 10 ** ((ref - rssi) / (10 * n))
    return {"min_m": round(d * 0.6, 1), "max_m": round(d * 1.6, 1), "est_m": round(d, 1)}


# ---------------------------------------------------------------- escaneo
def ping(ip, count=1, timeout_ms=800):
    out = sh(["ping", "-c", str(count), "-W", str(timeout_ms), "-i", "0.2", ip],
             timeout=count * 2 + 2)
    return [float(x) for x in re.findall(r"time=([\d.]+) ms", out)]


def arp_table():
    table = {}
    for line in sh(["arp", "-an"]).splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", line)
        if m and m.group(2) != "ff:ff:ff:ff:ff:ff":
            mac = ":".join(p.zfill(2) for p in m.group(2).split(":"))
            table[m.group(1)] = mac
    return table


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    # mDNS / Bonjour (nombres .local)
    out = sh(["dig", "+short", "+time=1", "+tries=1", "-x", ip, "@224.0.0.251", "-p", "5353"], timeout=3)
    lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith(";")]
    return lines[0].rstrip(".") if lines else None


def open_ports(ip):
    found = []
    for p, label in PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            if s.connect_ex((ip, p)) == 0:
                found.append({"port": p, "service": label})
        except Exception:
            pass
        finally:
            s.close()
    return found


def is_random_mac(mac):
    # bit "localmente administrado": típico de MACs privadas de iPhone/Android
    return bool(int(mac.split(":")[0], 16) & 0b10)


def vendor(mac):
    if not mac or is_random_mac(mac):
        return None
    oui = mac.upper().replace(":", "")[:6]
    with _vendor_lock:
        if oui in VENDOR_CACHE:
            return VENDOR_CACHE[oui]
    name = None
    try:
        # Solo se envía el prefijo del fabricante (OUI), no la MAC completa.
        req = urllib.request.Request(f"https://api.macvendors.com/{oui}",
                                     headers={"User-Agent": "wifi-scanner"})
        with urllib.request.urlopen(req, timeout=4) as r:
            name = r.read().decode().strip()
        time.sleep(1.1)  # límite de la API gratuita: ~1 petición/seg
    except Exception:
        name = None
    with _vendor_lock:
        VENDOR_CACHE[oui] = name
        try:
            VENDOR_CACHE_FILE.write_text(json.dumps(VENDOR_CACHE, indent=1))
        except Exception:
            pass
    return name


def guess_type(dev):
    v = (dev.get("vendor") or "").lower()
    h = (dev.get("hostname") or "").lower()
    ports = {p["port"] for p in dev["ports"]}
    if dev.get("is_gateway"):
        return "Router"
    if 62078 in ports or "iphone" in h or "ipad" in h:
        return "iPhone / iPad"
    if 8008 in ports or 8009 in ports or "chromecast" in h:
        return "Chromecast / Google TV"
    if 9100 in ports or 631 in ports or any(k in v for k in ("epson", "canon", "brother", "hewlett")):
        return "Impresora"
    if 554 in ports or any(k in v for k in ("hikvision", "dahua", "wyze", "ezviz")):
        return "Cámara"
    if any(k in h for k in ("macbook", "imac", "mac-")) or 548 in ports:
        return "Mac"
    if "android" in h or any(k in v for k in ("samsung", "xiaomi", "huawei", "oppo", "motorola", "oneplus")):
        return "Móvil / Android"
    if "aqara" in h or any(k in v for k in ("espressif", "tuya", "shelly", "sonoff", "lumi", "aqara", "fn-link", "philips")):
        return "IoT (enchufe, bombilla…)"
    if any(k in v for k in ("amazon",)) or "echo" in h:
        return "Amazon (Echo / Fire TV)"
    if any(k in v for k in ("lg ", "sony", "tcl", "hisense", "roku")):
        return "Smart TV"
    if 445 in ports:
        return "PC Windows / NAS"
    if 7000 in ports or "apple" in v:
        return "Dispositivo Apple"
    if dev.get("random_mac"):
        return "Móvil (MAC privada)"
    return "Desconocido"


def proximity(dev, router_rtt):
    """
    Estimación MUY aproximada usando la latencia y su variación.
    En WiFi, un dispositivo lejos / con mala señal suele tener más latencia
    y más jitter (retransmisiones). No es una medida de distancia real.
    """
    rtts = dev["rtts"]
    if not rtts:
        return {"label": "Sin respuesta a ping", "level": 0, "range": "desconocido"}
    med = statistics.median(rtts)
    jit = statistics.pstdev(rtts) if len(rtts) > 1 else 0
    loss = 1 - len(rtts) / dev["pings_sent"]
    score = med + 2 * jit + 60 * loss - (router_rtt or 0)
    if score < 8:
        return {"label": "Muy cerca / buena señal", "level": 4, "range": "~0–5 m (misma habitación)"}
    if score < 25:
        return {"label": "Cerca", "level": 3, "range": "~5–10 m (habitación contigua)"}
    if score < 70:
        return {"label": "Media distancia", "level": 2, "range": "~10–20 m (otra planta / varias paredes)"}
    return {"label": "Lejos / señal débil", "level": 1, "range": "> 20 m o señal muy débil"}


def scan():
    scan_state.update(running=True, progress=0, error=None)
    try:
        net = local_network()
        hosts = [str(h) for h in ipaddress.IPv4Network(net["network"]).hosts()]
        if len(hosts) > 1024:
            hosts = hosts[:1024]
        scan_state["total"] = len(hosts)

        # 1) barrido de ping para poblar la tabla ARP
        alive = set()

        def sweep(ip):
            if ping(ip, 1, 700):
                alive.add(ip)
            scan_state["progress"] += 1

        with ThreadPoolExecutor(128) as ex:
            list(ex.map(sweep, hosts))

        arp = arp_table()
        ips = sorted(set(arp) | alive | {net["ip"]},
                     key=lambda x: ipaddress.IPv4Address(x))
        ips = [i for i in ips if ipaddress.IPv4Address(i) in ipaddress.IPv4Network(net["network"])]

        # 2) detalles de cada dispositivo
        PINGS = 8

        def detail(ip):
            d = {"ip": ip, "mac": arp.get(ip), "is_self": ip == net["ip"],
                 "is_gateway": ip == net["gateway"], "pings_sent": PINGS}
            if d["is_self"]:
                d["mac"] = net["mac"]
            d["rtts"] = ping(ip, PINGS, 1000)
            d["hostname"] = hostname(ip)
            d["ports"] = open_ports(ip)
            d["random_mac"] = bool(d["mac"]) and is_random_mac(d["mac"])
            return d

        with ThreadPoolExecutor(32) as ex:
            devices = list(ex.map(detail, ips))

        for d in devices:  # secuencial por el límite de la API de fabricantes
            d["vendor"] = vendor(d["mac"])

        gw = next((d for d in devices if d["is_gateway"]), None)
        router_rtt = statistics.median(gw["rtts"]) if gw and gw["rtts"] else 0
        for d in devices:
            d["type"] = guess_type(d)
            if d["is_self"]:
                d["proximity"] = {"label": "Este equipo", "level": 5, "range": "aquí"}
            elif d["is_gateway"]:
                d["proximity"] = {"label": "Router", "level": 5, "range": "punto de referencia"}
            else:
                d["proximity"] = proximity(d, router_rtt)
            d["rtt_avg"] = round(statistics.mean(d["rtts"]), 1) if d["rtts"] else None
            d["loss_pct"] = round(100 * (1 - len(d["rtts"]) / PINGS))

        new = update_db(devices)
        scan_state["result"] = {"network": net, "wifi": wifi_info(), "devices": devices,
                                "new_devices": new, "scanned_at": now()}
    except Exception as e:
        scan_state["error"] = str(e)
    finally:
        scan_state["running"] = False


# ---------------------------------------------------------------- interfaz web
INDEX_HTML = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Escáner WiFi</title>
<style>
  :root { --bg:#0f1115; --card:#181b22; --line:#262a33; --fg:#e6e8ec; --mut:#8a909c; --acc:#4f8cff; --ok:#3ecf8e; --warn:#f5a524; --bad:#f2555a; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.45 -apple-system, system-ui, sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:16px 24px; display:flex; flex-wrap:wrap; gap:14px; align-items:center; justify-content:space-between; border-bottom:1px solid var(--line); }
  h1 { margin:0; font-size:20px; }
  .ctrls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
  button { background:var(--acc); color:#fff; border:0; padding:9px 16px; border-radius:8px; font-weight:600; cursor:pointer; font-size:13px; }
  button.ghost { background:#232836; color:var(--fg); font-weight:500; }
  button.small { padding:3px 8px; font-size:12px; }
  button:disabled { opacity:.5; cursor:default; }
  select, input[type=text] { background:#14171d; color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:7px 8px; font-size:13px; }
  label { color:var(--mut); font-size:13px; display:flex; gap:6px; align-items:center; }
  main { padding:20px 24px; max-width:1300px; margin:auto; }
  .bar { height:6px; background:var(--line); border-radius:4px; overflow:hidden; margin:0 0 12px; display:none; }
  .bar > div { height:100%; width:0; background:var(--acc); transition:width .3s; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-bottom:20px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
  .card b { display:block; font-size:18px; margin-top:4px; }
  .mut { color:var(--mut); font-size:12px; }
  .alert { display:none; background:#2a2312; border:1px solid #5c4813; color:#ffd88a; padding:12px 16px; border-radius:10px; margin-bottom:16px; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
  .tabs { display:flex; gap:4px; margin-bottom:14px; border-bottom:1px solid var(--line); }
  .tabs button { background:none; color:var(--mut); border-radius:0; border-bottom:2px solid transparent; padding:10px 14px; }
  .tabs button.on { color:var(--fg); border-color:var(--acc); }
  .pane { display:none; } .pane.on { display:block; }
  .wrap { display:grid; grid-template-columns: 340px 1fr; gap:20px; }
  @media (max-width: 900px) { .wrap { grid-template-columns: 1fr; } }
  svg text { fill:var(--mut); font-size:10px; }
  .tbl { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; background:var(--card); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--mut); font-weight:500; font-size:12px; background:#14171d; }
  tr:hover td { background:#1d212a; }
  .tag { display:inline-block; padding:1px 6px; border-radius:4px; background:#232836; font-size:11px; margin:1px; }
  .tag.new { background:var(--warn); color:#000; font-weight:700; }
  .tag.ev-nuevo { background:var(--warn); color:#000; }
  .tag.ev-conectado { background:#173d2c; color:var(--ok); }
  .tag.ev-desconectado { background:#40191b; color:var(--bad); }
  .tag.ev-inicial { background:#1b2a47; color:#9bbcff; }
  .lvl { display:inline-flex; gap:2px; vertical-align:middle; margin-right:6px; }
  .lvl i { width:5px; height:12px; background:var(--line); border-radius:1px; }
  .lvl i.on { background:var(--ok); }
  .edit { background:none; border:0; color:var(--mut); cursor:pointer; padding:0 4px; font-size:13px; }
  .edit:hover { color:var(--fg); }
  code { font-size:12px; }
  .note { background:#1a1f2b; border-left:3px solid var(--warn); padding:10px 14px; border-radius:6px; color:var(--mut); margin-top:20px; font-size:13px; }
  .err { color:var(--bad); }
  .empty { padding:30px; text-align:center; color:var(--mut); background:var(--card); border-radius:10px; }
</style>
</head>
<body>
<header>
  <div><h1>📶 Escáner de mi WiFi</h1><div class="mut" id="sub">Pulsa “Escanear” para ver los dispositivos conectados</div></div>
  <div class="ctrls">
    <label>Escaneo automático
      <select id="interval">
        <option value="0">Apagado</option><option value="2">cada 2 min</option><option value="5">cada 5 min</option>
        <option value="10">cada 10 min</option><option value="15">cada 15 min</option><option value="30">cada 30 min</option><option value="60">cada hora</option>
      </select>
    </label>
    <label><input type="checkbox" id="macnotify"> Aviso en el Mac</label>
    <button id="btn">Escanear</button>
  </div>
</header>
<main>
  <div class="bar" id="bar"><div></div></div>
  <div id="status" class="mut" style="margin-bottom:10px"></div>
  <div class="alert" id="alert"><span id="alertText"></span><button class="small" id="ack">Marcar como vistos</button></div>
  <div class="grid" id="summary"></div>

  <div class="tabs">
    <button data-tab="now" class="on">Conectados <span id="cNow" class="tag"></span></button>
    <button data-tab="hist">Historial</button>
    <button data-tab="off">Desconectados <span id="cOff" class="tag"></span></button>
  </div>

  <section class="pane on" id="pane-now">
    <div class="wrap" id="wrap" style="display:none">
      <div class="card">
        <div class="mut">Mapa de proximidad (aprox.)</div>
        <svg id="radar" viewBox="-180 -180 360 360" width="100%"></svg>
        <div class="mut">Centro = este equipo. Más lejos del centro = más latencia / peor señal.</div>
      </div>
      <div class="tbl">
        <table>
          <thead><tr><th>Dispositivo</th><th>IP / MAC</th><th>Fabricante</th><th>Servicios</th><th>Latencia</th><th>Proximidad aprox.</th></tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </div>
    <div class="empty" id="emptyNow">Todavía no hay escaneos.</div>
    <div class="note">
      <b>Sobre la ubicación:</b> desde un ordenador no se puede medir la señal que recibe el router de cada dispositivo,
      así que la “proximidad” se estima con la latencia, su variación (jitter) y la pérdida de paquetes. Es solo orientativa.
      La distancia a tu router sí se calcula con la señal real (RSSI) de tu WiFi.
    </div>
  </section>

  <section class="pane" id="pane-hist">
    <div style="margin-bottom:10px"><label>Filtrar por dispositivo <select id="histFilter"><option value="">Todos</option></select></label></div>
    <div class="tbl"><table>
      <thead><tr><th>Fecha y hora</th><th>Evento</th><th>Dispositivo</th><th>IP</th></tr></thead>
      <tbody id="histRows"></tbody>
    </table></div>
    <div class="note">Un dispositivo cuenta como desconectado cuando deja de aparecer en un escaneo. macOS recuerda los dispositivos unos minutos,
      así que la desconexión puede detectarse con hasta ~20 min de retraso.</div>
  </section>

  <section class="pane" id="pane-off">
    <div class="tbl"><table>
      <thead><tr><th>Dispositivo</th><th>Última IP / MAC</th><th>Fabricante</th><th>Visto por primera vez</th><th>Última vez</th><th></th></tr></thead>
      <tbody id="offRows"></tbody>
    </table></div>
  </section>
</main>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const icons = {"Router":"🛜","iPhone / iPad":"📱","Móvil / Android":"📱","Móvil (MAC privada)":"📱","Mac":"💻","PC Windows / NAS":"🖥️",
  "Impresora":"🖨️","Cámara":"📷","Chromecast / Google TV":"📺","Smart TV":"📺","Amazon (Echo / Fire TV)":"🔊","IoT (enchufe, bombilla…)":"💡",
  "Dispositivo Apple":"","Desconocido":"❔"};
const evLabel = {nuevo:"Nuevo", conectado:"Conectado", desconectado:"Desconectado", inicial:"Primer escaneo"};
const api = (path, body) => fetch(path, body === undefined ? {} : {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)}).then(r => r.json());

let last = null, lastScanAt = null, notifiedFor = null, editing = false;

// ---- pestañas
document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
  document.querySelectorAll(".tabs button").forEach(x => x.classList.toggle("on", x === b));
  document.querySelectorAll(".pane").forEach(p => p.classList.toggle("on", p.id === "pane-" + b.dataset.tab));
});

// ---- controles
$("#btn").onclick = async () => { await api("/api/scan", {}); tick(); };
$("#interval").onchange = async e => {
  const v = +e.target.value;
  if (v && "Notification" in window && Notification.permission === "default") Notification.requestPermission();
  await api("/api/settings", {interval_min: v}); tick();
};
$("#macnotify").onchange = e => api("/api/settings", {mac_notify: e.target.checked});
$("#ack").onclick = async () => { await api("/api/ack", {}); load(); };
$("#histFilter").onchange = () => renderHistory();

// ---- estado (cada 3 s)
async function tick() {
  let s;
  try { s = await api("/api/status"); } catch { $("#status").innerHTML = '<span class="err">No hay conexión con el servidor (¿está corriendo app.py?)</span>'; return; }
  $("#btn").disabled = s.running;
  $("#bar").style.display = s.running ? "block" : "none";
  if (s.running && s.total) $("#bar > div").style.width = Math.min(95, 70 * s.progress / s.total + (s.progress >= s.total ? 20 : 0)) + "%";
  $("#status").innerHTML = s.error ? `<span class="err">Error: ${esc(s.error)}</span>`
    : s.running ? (s.progress < s.total || !s.total ? `Buscando dispositivos… ${s.progress}/${s.total}` : "Analizando dispositivos (latencia, puertos, fabricante)…")
    : s.next_scan ? `Próximo escaneo automático a las ${s.next_scan}` : "";
  if (!s.running && s.scanned_at && s.scanned_at !== lastScanAt) { lastScanAt = s.scanned_at; load(); }
}

async function load() {
  last = await api("/api/result");
  render();
}

function bars(l) { return `<span class="lvl">${[1,2,3,4].map(i => `<i class="${i <= l ? "on" : ""}"></i>`).join("")}</span>`; }

function nameCell(d, fallback) {
  const name = d.alias || d.hostname || fallback;
  const sub = d.alias ? (d.hostname || d.type || "") : (d.type || "");
  return `<span class="nm" data-key="${esc(d.key)}" data-alias="${esc(d.alias || "")}"><b>${esc(name)}</b><button class="edit" title="Ponerle nombre">✏️</button></span>
    ${d.is_self ? '<span class="tag">tú</span>' : ""}${d.is_new ? '<span class="tag new">NUEVO</span>' : ""}<br><span class="mut">${esc(sub)}</span>`;
}

function render() {
  const r = last || {};
  const s = r.settings || {};
  $("#interval").value = String(s.interval_min || 0);
  $("#macnotify").checked = s.mac_notify !== false;

  // nuevos
  const nuevos = (r.devices || []).filter(d => d.is_new);
  $("#alert").style.display = nuevos.length ? "flex" : "none";
  $("#alertText").innerHTML = `⚠️ <b>${nuevos.length === 1 ? "Dispositivo nuevo" : nuevos.length + " dispositivos nuevos"}</b> en tu red: ` +
    nuevos.map(d => esc(d.alias || d.hostname || d.vendor || d.ip) + ` (${esc(d.ip)})`).join(", ");
  if (nuevos.length && r.scanned_at !== notifiedFor && "Notification" in window && Notification.permission === "granted" && document.hidden) {
    new Notification("Nuevo dispositivo en tu WiFi", {body: nuevos.map(d => (d.hostname || d.vendor || "Desconocido") + " · " + d.ip).join("\n")});
  }
  notifiedFor = r.scanned_at;

  $("#cOff").textContent = (r.offline || []).length;
  renderOffline(); renderHistory();
  if (!r.devices) return;

  const n = r.network, w = r.wifi || {};
  $("#sub").textContent = `Último escaneo: ${r.scanned_at}`;
  $("#cNow").textContent = r.devices.length;
  const dist = w.router_distance ? `${w.router_distance.min_m}–${w.router_distance.max_m} m` : "—";
  $("#summary").innerHTML = [
    ["Red", w.ssid || n.iface], ["Conectados", r.devices.length], ["Nuevos", nuevos.length], ["Mi IP", n.ip],
    ["Señal WiFi", w.rssi ? `${w.rssi} dBm` : "—"], ["Distancia a router (aprox.)", dist],
  ].map(([k, v]) => `<div class="card"><span class="mut">${k}</span><b>${esc(v)}</b></div>`).join("");

  const devs = r.devices.slice().sort((a, b) => (b.is_new - a.is_new) || (b.proximity.level - a.proximity.level) || ((a.rtt_avg ?? 1e9) - (b.rtt_avg ?? 1e9)));
  $("#rows").innerHTML = devs.map(d => `
    <tr>
      <td>${icons[d.type] ?? "❔"} ${nameCell(d, d.type)}</td>
      <td><code>${esc(d.ip)}</code><br><code class="mut">${esc(d.mac || "—")}</code>${d.random_mac ? '<br><span class="tag">MAC privada</span>' : ""}</td>
      <td>${esc(d.vendor || (d.random_mac ? "Oculto (MAC aleatoria)" : "Desconocido"))}</td>
      <td>${d.ports.map(p => `<span class="tag">${p.port} ${esc(p.service)}</span>`).join("") || '<span class="mut">—</span>'}</td>
      <td>${d.rtt_avg != null ? d.rtt_avg + " ms" : "—"}<br><span class="mut">pérdida ${d.loss_pct}%</span></td>
      <td>${d.proximity.level <= 4 ? bars(d.proximity.level) : ""}${esc(d.proximity.label)}<br><span class="mut">${esc(d.proximity.range)}</span></td>
    </tr>`).join("");
  drawRadar(devs);
  $("#wrap").style.display = "grid"; $("#emptyNow").style.display = "none";
}

function renderOffline() {
  const off = (last && last.offline) || [];
  $("#offRows").innerHTML = off.length ? off.map(d => `
    <tr>
      <td>${icons[d.type] ?? "❔"} ${nameCell(d, (d.type || "Dispositivo"))}</td>
      <td><code>${esc(d.last_ip || "—")}</code><br><code class="mut">${esc(d.key.startsWith("ip:") ? "—" : d.key)}</code></td>
      <td>${esc(d.vendor || "Desconocido")}</td>
      <td>${esc(d.first_seen || "—")}</td>
      <td>${esc(d.last_seen || "—")}</td>
      <td><button class="small ghost forget" data-key="${esc(d.key)}">Olvidar</button></td>
    </tr>`).join("") : '<tr><td colspan="6" class="mut">Ningún dispositivo conocido está desconectado.</td></tr>';
}

function renderHistory() {
  const ev = (last && last.events) || [];
  const sel = $("#histFilter"), cur = sel.value;
  const names = new Map(); ev.forEach(e => names.has(e.key) || names.set(e.key, e.name));
  sel.innerHTML = '<option value="">Todos</option>' + [...names].sort((a, b) => a[1].localeCompare(b[1])).map(([k, n]) => `<option value="${esc(k)}">${esc(n)}</option>`).join("");
  sel.value = names.has(cur) ? cur : "";
  const list = ev.filter(e => !sel.value || e.key === sel.value);
  $("#histRows").innerHTML = list.length ? list.map(e => `
    <tr><td>${esc(e.t)}</td><td><span class="tag ev-${esc(e.kind)}">${esc(evLabel[e.kind] || e.kind)}</span></td><td>${esc(e.name)}</td><td><code>${esc(e.ip || "—")}</code></td></tr>`).join("")
    : '<tr><td colspan="4" class="mut">Sin eventos todavía.</td></tr>';
}

// ---- editar nombre y olvidar (delegación de eventos)
document.addEventListener("click", async e => {
  const ed = e.target.closest(".edit");
  if (ed) {
    const span = ed.closest(".nm");
    if (span.querySelector("input")) return;
    editing = true;
    span.innerHTML = `<input type="text" placeholder="Ej: Móvil de mamá" value="${esc(span.dataset.alias)}" maxlength="60" style="width:170px">`;
    const inp = span.querySelector("input"); inp.focus(); inp.select();
    let done = false;
    const save = async (ok) => {
      if (done) return; done = true; editing = false;
      if (ok) await api("/api/alias", {key: span.dataset.key, alias: inp.value});
      load();
    };
    inp.onkeydown = ev => { if (ev.key === "Enter") save(true); if (ev.key === "Escape") save(false); };
    inp.onblur = () => save(true);
    return;
  }
  const fg = e.target.closest(".forget");
  if (fg) {
    if (fg.dataset.confirm) { await api("/api/forget", {key: fg.dataset.key}); load(); }
    else { fg.dataset.confirm = 1; fg.textContent = "¿Seguro?"; fg.style.background = "var(--bad)"; setTimeout(() => { delete fg.dataset.confirm; fg.textContent = "Olvidar"; fg.style.background = ""; }, 3000); }
  }
});

function drawRadar(devs) {
  const R = [40, 80, 120, 160], labels = ["0–5 m", "5–10 m", "10–20 m", ">20 m"];
  let svg = R.map((r, i) => `<circle r="${r}" fill="none" stroke="#262a33"/><text x="3" y="${-r + 11}">${labels[i]}</text>`).join("");
  const others = devs.filter(d => !d.is_self);
  others.forEach((d, i) => {
    const lvl = d.proximity.level >= 5 ? 4 : (d.proximity.level || 1);
    const r = (R[4 - lvl] - 20) + ((i * 7) % 16);
    const a = (i / others.length) * Math.PI * 2 - Math.PI / 2;
    const x = Math.cos(a) * r, y = Math.sin(a) * r;
    const col = d.is_gateway ? "#4f8cff" : ["#8a909c", "#f2555a", "#f5a524", "#a3d65c", "#3ecf8e"][d.proximity.level] || "#8a909c";
    const label = d.alias || d.ip.split(".").pop();
    svg += `<g><title>${esc((d.alias || d.hostname || d.type) + " · " + d.ip + " · " + d.proximity.range)}</title>
      <circle cx="${x}" cy="${y}" r="7" fill="${col}" ${d.is_new ? 'stroke="#f5a524" stroke-width="3"' : ""}/><text x="${x + 10}" y="${y + 3}">${esc(label)}</text></g>`;
  });
  svg += `<circle r="9" fill="#fff"/><text x="12" y="4" style="fill:#fff">tú</text>`;
  $("#radar").innerHTML = svg;
}

load().then(() => { if (last && last.scanned_at) lastScanAt = last.scanned_at; });
setInterval(() => { if (!editing) tick(); }, 3000);
tick();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- servidor
class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            st = {k: scan_state[k] for k in ("running", "progress", "total", "error", "next_scan")}
            st["scanned_at"] = (scan_state["result"] or {}).get("scanned_at")
            self._json(st)
        elif self.path == "/api/result":
            self._json(full_result())
        else:
            self._json({"error": "not found"}, 404)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_POST(self):
        if self.path == "/api/scan":
            start_scan()
            self._json({"started": True})
        elif self.path == "/api/alias":
            b = self._body()
            with _db_lock:
                rec = DB["devices"].get(b.get("key"))
                if not rec:
                    return self._json({"error": "dispositivo desconocido"}, 404)
                alias = str(b.get("alias") or "").strip()[:60]
                if alias:
                    rec["alias"] = alias
                else:
                    rec.pop("alias", None)
                save_db()
            self._json({"ok": True})
        elif self.path == "/api/ack":          # marcar "nuevos" como vistos
            with _db_lock:
                for rec in DB["devices"].values():
                    rec.pop("unacknowledged", None)
                save_db()
            self._json({"ok": True})
        elif self.path == "/api/forget":       # olvidar un dispositivo desconectado
            b = self._body()
            with _db_lock:
                DB["devices"].pop(b.get("key"), None)
                save_db()
            self._json({"ok": True})
        elif self.path == "/api/settings":
            b = self._body()
            with _db_lock:
                if "interval_min" in b:
                    DB["settings"]["interval_min"] = max(0, min(1440, int(b["interval_min"] or 0)))
                if "mac_notify" in b:
                    DB["settings"]["mac_notify"] = bool(b["mac_notify"])
                save_db()
            self._json({"ok": True, "settings": DB["settings"]})
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    threading.Thread(target=auto_scan_loop, daemon=True).start()
    print(f"Abre http://localhost:{args.port}  (Ctrl+C para salir)")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
