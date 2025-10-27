# main.py — Pico W (MicroPython)
# Uptime-lite: Web UI + Basic Auth + /health + Telegram (solo variazioni)
# Modalità: http / tcp / ping(icmp) — Porta HTTP configurabile, log e LED

import network, time, socket, ssl, json, os, gc, machine
try:
    import uhashlib as hashlib
except:
    import hashlib
try:
    import ubinascii as binascii
except:
    import binascii
try:
    import ustruct as struct
except:
    import struct

LED = machine.Pin("LED", machine.Pin.OUT)

# =======================
# ======= CONFIG ========
# =======================
CONFIG = {
    "WIFI_SSID": "Inserisci il tuo SSID",
    "WIFI_PASSWORD": "inserisci la tua PSW",

    # usa 8080 se 80 crea problemi
    "HTTP_PORT": 8080,

    "CHECK_INTERVAL": 15,
    "DOWN_THRESHOLD": 2,
    "UP_THRESHOLD": 2,

    "TELEGRAM_ENABLED": True,
    "TELEGRAM_BOT_TOKEN": "inserisci il token del tuo bot",
    "TELEGRAM_CHAT_ID": "inserisci il tuo chat id",

    "TARGETS_FILE": "targets.json",
}

# ======= AUTH ========
# genera l'hash con:
#   python - <<'PY'
#   import hashlib; print(hashlib.sha256(b"tuaPasswordQui").hexdigest())
#   PY
AUTH = {
    "USER": "admin",
    "PASS_SHA256": "sha256psw",
    "MAX_FAILS": 5,
    "BLOCK_SECONDS": 30,
    # token opzionale per /health pubblico (altrimenti Basic Auth)
    "HEALTH_PUBLIC_TOKEN": "",
}

# ---- Persistenza impostazioni runtime ----
CONFIG_FILE = "config.json"

def load_runtime_config():
    try:
        if CONFIG_FILE in os.listdir():
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
            # Solo i tre parametri esposti in UI
            ci = int(data.get("CHECK_INTERVAL", CONFIG["CHECK_INTERVAL"]))
            up = int(data.get("UP_THRESHOLD",   CONFIG["UP_THRESHOLD"]))
            dn = int(data.get("DOWN_THRESHOLD", CONFIG["DOWN_THRESHOLD"]))
            # Validazione minima
            CONFIG["CHECK_INTERVAL"] = max(5, min(ci, 3600))
            CONFIG["UP_THRESHOLD"]   = max(1, min(up, 10))
            CONFIG["DOWN_THRESHOLD"] = max(1, min(dn, 10))
            print("[CFG] runtime loaded:", CONFIG["CHECK_INTERVAL"], CONFIG["UP_THRESHOLD"], CONFIG["DOWN_THRESHOLD"])
    except Exception as e:
        print("[CFG] load error:", repr(e))

def save_runtime_config():
    try:
        data = {
            "CHECK_INTERVAL": CONFIG["CHECK_INTERVAL"],
            "UP_THRESHOLD":   CONFIG["UP_THRESHOLD"],
            "DOWN_THRESHOLD": CONFIG["DOWN_THRESHOLD"],
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)
        return True
    except Exception as e:
        print("[CFG] save error:", repr(e))
        return False

# =======================
# ====== TARGET IO ======
# =======================
def load_targets():
    fname = CONFIG["TARGETS_FILE"]
    if fname in os.listdir():
        try:
            with open(fname, "r") as f:
                data = json.load(f)
                out = []
                for t in data:
                    mode = t.get("mode")
                    name = t.get("name", "target")
                    if mode == "http" and t.get("url"):
                        out.append({"name": name, "mode": "http", "url": t["url"]})
                    elif mode == "tcp" and t.get("host") and int(t.get("port", 0)) > 0:
                        out.append({"name": name, "mode": "tcp", "host": t["host"], "port": int(t["port"])})
                    elif mode == "ping" and t.get("host"):
                        out.append({"name": name, "mode": "ping", "host": t["host"]})
                return out
        except:
            pass
    return []

def save_targets(targets):
    try:
        with open(CONFIG["TARGETS_FILE"], "w") as f:
            json.dump(targets, f)
        return True
    except:
        return False

# =======================
# ======= NET/UTIL ======
# =======================
def wifi_connect(ssid, password, timeout=25):
    print("[WiFi] connecting to", ssid, "...")
    LED.off()
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        wlan.connect(ssid, password)
        t0 = time.ticks_ms()
        while not wlan.isconnected():
            LED.toggle()
            time.sleep(0.25)
            if time.ticks_diff(time.ticks_ms(), t0) > timeout * 1000:
                print("[WiFi] timeout.")
                LED.off()
                return False
    ip = wlan.ifconfig()[0]
    print("[WiFi] connected, IP:", ip)
    LED.on()
    return True

def url_encode(s):
    # application/x-www-form-urlencoded UTF-8
    SAFE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
    out = []
    for b in s.encode("utf-8"):        # << encode UTF-8, poi encoda byte per byte
        if b == 0x20:                  # spazio -> '+'
            out.append('+')
        elif b in SAFE:
            out.append(chr(b))
        else:
            out.append('%{:02X}'.format(b))
    return ''.join(out)

def html_escape(s):
    return (s.replace("&","&amp;")
             .replace("<","&lt;")
             .replace(">","&gt;")
             .replace('"',"&quot;"))

def parse_qs(qs):
    params = {}
    for part in qs.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        k = k.replace("+"," "); v = v.replace("+"," ")
        def pct(x):
            res = b""; xb = x.encode(); i = 0
            while i < len(xb):
                if xb[i:i+1] == b'%' and i+2 < len(xb):
                    try:
                        res += bytes([int(xb[i+1:i+3], 16)]); i += 3; continue
                    except: pass
                res += xb[i:i+1]; i += 1
            try: return res.decode()
            except: return x
        params[pct(k)] = pct(v)
    return params

def parse_url(url):
    scheme = "http"; port = 80; path = "/"
    rest = url
    if "://" in url:
        scheme, rest = url.split("://", 1)
    if "/" in rest:
        hostport, path = rest.split("/", 1); path = "/" + path
    else:
        hostport = rest; path = "/"
    if ":" in hostport:
        host, p = hostport.split(":", 1); port = int(p)
    else:
        host = hostport; port = 443 if scheme == "https" else 80
    return scheme, host, port, path

# =======================
# ====== CHECKERS =======
# =======================
def check_tcp(host, port, timeout=3):
    s = None
    try:
        addr = socket.getaddrinfo(host, port)[0][-1]
        s = socket.socket(); s.settimeout(timeout); s.connect(addr)
        return True
    except:
        return False
    finally:
        try:
            if s: s.close()
        except:
            pass

def check_http(url, timeout=4):
    scheme, host, port, path = parse_url(url)
    s = None
    try:
        addr = socket.getaddrinfo(host, port)[0][-1]
        s = socket.socket(); s.settimeout(timeout); s.connect(addr)
        if scheme == "https":
            s = ssl.wrap_socket(s, server_hostname=host)
        req = "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: PicoWatch/1\r\n\r\n".format(path, host)
        s.write(req.encode())
        data = s.read(64)
        if not data:
            return False, None
        line = data.split(b"\r\n", 1)[0]
        parts = line.split()
        status = int(parts[1]) if len(parts) > 1 else 0
        return (status < 400), status
    except:
        return False, None
    finally:
        try:
            if s: s.close()
        except:
            pass

# ----- PING (ICMP) -----
def _icmp_checksum(data):
    if len(data) & 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def check_ping(host, timeout_ms=1000, seq=1, payload_size=8):
    """
    Ritorna (ok, rtt_ms) — ok=False se timeout/errore, rtt_ms=None se non disponibile.
    """
    s = None
    try:
        dest = socket.getaddrinfo(host, 1)[0][-1][0]
        # SOCK_RAW + IPPROTO_ICMP
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
        s.settimeout(timeout_ms / 1000.0)

        ident = 0xABCD  # qualunque
        payload = b'Q' * payload_size
        header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)  # type=8 echo, code=0, csum=0
        csum = _icmp_checksum(header + payload)
        packet = struct.pack("!BBHHH", 8, 0, csum, ident, seq) + payload

        t0 = time.ticks_ms()
        s.sendto(packet, (dest, 1))
        resp = s.recv(128)
        t1 = time.ticks_ms()

        # parse IP header to locate ICMP
        ihl = (resp[0] & 0x0F) * 4
        icmp = resp[ihl:ihl+8]
        if len(icmp) < 8:
            return False, None
        r_type, r_code, r_csum, r_ident, r_seq = struct.unpack("!BBHHH", icmp)
        if r_type == 0 and r_ident == ident and r_seq == seq:
            rtt = time.ticks_diff(t1, t0)
            return True, int(rtt)
        return False, None
    except:
        return False, None
    finally:
        try:
            if s: s.close()
        except:
            pass

# =======================
# ===== NOTIFICHE =======
# =======================
def telegram_send(bot_token, chat_id, text):
    host = "api.telegram.org"; port = 443
    path = "/bot{}/sendMessage".format(bot_token)
    payload = "chat_id={}&text={}&disable_web_page_preview=1".format(
        url_encode(str(chat_id)), url_encode(text)
    )
    req = (
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: {}\r\n\r\n{}"
    ).format(path, host, len(payload), payload)

    s = None
    try:
        addr = socket.getaddrinfo(host, port)[0][-1]
        s = socket.socket(); s.settimeout(6); s.connect(addr)
        s = ssl.wrap_socket(s, server_hostname=host)
        s.write(req.encode())
        # opzionale: controlla l'esito
        resp = s.read() or b""
        if b'"ok":true' not in resp:
            try:
                print("[TG] fail:", resp.split(b"\r\n\r\n",1)[-1].decode())
            except:
                print("[TG] fail (raw)")
        return True
    except Exception as e:
        print("[TG] error:", repr(e))
        return False
    finally:
        try:
            if s: s.close()
        except:
            pass

def notify(text):
    if CONFIG["TELEGRAM_ENABLED"]:
        telegram_send(CONFIG["TELEGRAM_BOT_TOKEN"], CONFIG["TELEGRAM_CHAT_ID"], text)

# =======================
# ====== BASIC AUTH =====
# =======================
_auth_state = {"fails": 0, "blocked_until": 0}

def sha256_hex(b):
    h = hashlib.sha256(b)
    try:
        return binascii.hexlify(h.digest()).decode()
    except:
        return "".join("{:02x}".format(x) for x in h.digest())

def parse_headers(raw):
    try:
        head = raw.split(b"\r\n\r\n", 1)[0].decode()
    except:
        head = ""
    lines = head.split("\r\n")[1:]
    headers = {}
    for ln in lines:
        if ":" in ln:
            k,v = ln.split(":",1)
            headers[k.strip().lower()] = v.strip()
    return headers

def check_basic_auth(headers, now_ms):
    global _auth_state
    if _auth_state["blocked_until"] and time.ticks_diff(now_ms, _auth_state["blocked_until"]) < 0:
        return (False, "429 Too Many Requests", True)
    auth = headers.get("authorization", "")
    if auth.startswith("Basic "):
        try:
            raw = auth.split(" ",1)[1]
            creds = binascii.a2b_base64(raw).decode()  # "user:pass"
            user, pwd = (creds.split(":",1)+[""])[:2] if ":" in creds else (creds, "")
            if user == AUTH["USER"] and sha256_hex(pwd.encode()) == AUTH["PASS_SHA256"]:
                _auth_state["fails"] = 0
                _auth_state["blocked_until"] = 0
                return (True, "200 OK", False)
        except:
            pass
    _auth_state["fails"] += 1
    if _auth_state["fails"] >= AUTH["MAX_FAILS"]:
        _auth_state["blocked_until"] = time.ticks_add(now_ms, AUTH["BLOCK_SECONDS"] * 1000)
        _auth_state["fails"] = 0
        return (False, "429 Too Many Requests", True)
    return (False, "401 Unauthorized", False)

def http_response(conn, status="200 OK", ctype="text/html; charset=utf-8", body="", extra_headers=None):
    try:
        hdrs = [
            "HTTP/1.1 {}".format(status),
            "Server: Pico",
            "Content-Type: {}".format(ctype),
            "Content-Length: {}".format(len(body) if isinstance(body,str) else len(body)),
            "Connection: close",
        ]
        if extra_headers: hdrs.extend(extra_headers)
        conn.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode())
        if isinstance(body, str): conn.sendall(body.encode())
        else: conn.sendall(body)
    except:
        pass

# =======================
# ======= WEB UI ========
# =======================
def render_page(targets, states, flash=""):
    rows = []
    for i, t in enumerate(targets):
        st = states[i]["status"] if i < len(states) else None
        code = states[i].get("last_code") if i < len(states) else None
        badge = "⚪ unknown"
        if t["mode"] == "ping":
            if st is True:
                badge = "🟢 UP" + ("" if code is None else " ({} ms)".format(code))
            elif st is False:
                badge = "🔴 DOWN (ping)"
        else:
            if st is True:
                badge = "🟢 UP"
            elif st is False:
                badge = "🔴 DOWN" + ("" if code is None else " (HTTP {})".format(code))

        if t["mode"] == "http":
            desc = html_escape(t["url"])
        elif t["mode"] == "tcp":
            desc = "{}:{}".format(html_escape(t["host"]), t["port"])
        else:  # ping
            desc = "{} (ICMP)".format(html_escape(t["host"]))

        rows.append(
            "<tr>"
            "<td>{}</td><td>{}</td><td><code>{}</code></td>"
            "<td style='text-align:center'>{}</td>"
            "<td style='text-align:right'>"
            "<a href='/test?i={}'>Test</a> | "
            "<a href='/del?i={}' onclick='return confirm(\"Eliminare?\")'>Del</a>"
            "</td>"
            "</tr>".format(
                html_escape(t.get("name", "target")),
                html_escape(t["mode"]),
                desc,
                badge,
                i, i
            )
        )

    flash_html = "" if not flash else "<div class='flash'>{}</div>".format(html_escape(flash))
    token_hint = "" if not AUTH["HEALTH_PUBLIC_TOKEN"] else ", oppure usa <code>?token=***</code>"

    html = """<!doctype html>
<html><head>
<meta charset="utf-8">
<title>Pico Uptime</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;max-width:900px;margin:24px auto;padding:0 12px;}}
table{{width:100%%;border-collapse:collapse;margin:12px 0;}}
th,td{{border:1px solid #ddd;padding:8px;}}
th{{background:#f2f2f2;text-align:left;}}
fieldset{{margin-top:16px;border:1px solid #ddd;}}
legend{{padding:0 6px;color:#444}}
input,select{{padding:6px;margin:4px 0;min-width:220px;}}
.btn{{display:inline-block;padding:8px 12px;border:1px solid #444;background:#fafafa;cursor:pointer;text-decoration:none}}
.flash{{padding:10px;background:#ffffcc;border:1px solid #e6db55;margin-bottom:10px}}
.small{{color:#666;font-size:12px}}
</style>
</head><body>
<h1>🧭 Pico Uptime</h1>
<p class="small">UI protetta da Basic Auth. Ricevi Telegram solo su variazione UP/DOWN.</p>
{flash}
<table>
<thead><tr><th>Nome</th><th>Modo</th><th>Endpoint</th><th>Stato</th><th style='text-align:right'>Azioni</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>

<fieldset>
<legend>Aggiungi target</legend>
<form action="/add" method="get">
  <label>Nome<br><input type="text" name="name" placeholder="NAS HTTP"></label><br>
  <label>Modo<br>
    <select name="mode" id="mode" onchange="onModeChange(this.value)">
      <option value="http">http/https</option>
      <option value="tcp">tcp</option>
      <option value="ping">ping (ICMP)</option>
    </select>
  </label><br>
  <div id="httpFields">
    <label>URL<br><input type="text" name="url" placeholder="http://10.10.99.253/"></label><br>
  </div>
  <div id="hostFields" style="display:none">
    <label>Host<br><input type="text" name="host" placeholder="10.10.99.254"></label><br>
  </div>
  <div id="portField" style="display:none">
    <label>Porta<br><input type="number" name="port" placeholder="1883"></label><br>
  </div>
  <button class="btn" type="submit">Aggiungi</button>
</form>
</fieldset>

<p class="small">Health: <a href="/health">/health</a> (aggiungi <code>?json=1</code>{token_hint}).</p>
<fieldset>
<legend>Impostazioni</legend>
<form action="/set" method="get">
  <label>Intervallo polling (s)<br>
    <input type="number" name="ci" min="5" max="3600" value="{ci}">
  </label><br>
  <label>Soglia UP (n. esiti OK consecutivi)<br>
    <input type="number" name="up" min="1" max="10" value="{up}">
  </label><br>
  <label>Soglia DOWN (n. esiti KO consecutivi)<br>
    <input type="number" name="dn" min="1" max="10" value="{dn}">
  </label><br>
  <button class="btn" type="submit">Salva</button>
</form>
<p class="small">Valori consigliati: intervallo 15–60s, soglie 1–3.</p>
</fieldset>

<script>
function onModeChange(v){{     // << raddoppia graffe
  document.getElementById('httpFields').style.display = (v==='http')?'block':'none';
  document.getElementById('hostFields').style.display = (v==='tcp' || v==='ping')?'block':'none';
  document.getElementById('portField').style.display = (v==='tcp')?'block':'none';
}}                              // << raddoppia graffe
</script>

</body></html>
""".format(flash=flash_html, rows="\n".join(rows), token_hint=token_hint,
           ci=CONFIG["CHECK_INTERVAL"], up=CONFIG["UP_THRESHOLD"], dn=CONFIG["DOWN_THRESHOLD"])


    return html

# =======================
# ======= HEALTH ========
# =======================
def health_dict(uptime_start_ms, targets, states):
    try:
        wlan = network.WLAN(network.STA_IF)
        ip = wlan.ifconfig()[0] if wlan.isconnected() else "0.0.0.0"
    except:
        ip = "0.0.0.0"
    up_s = time.ticks_diff(time.ticks_ms(), uptime_start_ms) // 1000
    mem_free = gc.mem_free()
    ok = sum(1 for s in states if s.get("status") is True)
    down = sum(1 for s in states if s.get("status") is False)
    unk = len(states) - ok - down
    return {
        "status": "ok",
        "uptime_s": int(up_s),
        "ip": ip,
        "targets": len(targets),
        "up": ok, "down": down, "unknown": unk,
        "heap_free": int(mem_free),
        "interval_s": CONFIG["CHECK_INTERVAL"],
        "http_port": CONFIG.get("HTTP_PORT", 80),
    }

# ------- Server socket globale -------
SERVER_SOCK = None

def ensure_server_socket():
    global SERVER_SOCK
    if SERVER_SOCK is not None:
        return True
    try:
        port = CONFIG.get("HTTP_PORT", 80)
        s = socket.socket()
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            pass
        s.bind(("0.0.0.0", port))
        s.listen(2)
        s.settimeout(0.2)
        SERVER_SOCK = s
        print("[HTTP] listening on port", port)
        return True
    except Exception as e:
        print("[HTTP] create socket error:", repr(e))
        try:
            if s: s.close()
        except:
            pass
        SERVER_SOCK = None
        gc.collect()
        time.sleep(0.3)
        return False

def serve_once(targets, states, uptime_start_ms):
    global SERVER_SOCK
    if not ensure_server_socket():
        return targets, states
    try:
        try:
            conn, addr = SERVER_SOCK.accept()
        except OSError:
            return targets, states
        conn.settimeout(1.0)

        data = b""
        try:
            data = conn.recv(1024)
        except:
            conn.close(); return targets, states
        if not data:
            conn.close(); return targets, states

        try:
            line = data.split(b"\r\n", 1)[0].decode()
        except:
            line = "GET / HTTP/1.1"
        parts = line.split(" ")
        method, fullpath = (parts[0], parts[1]) if len(parts) >= 2 else ("GET","/")
        path, qs = (fullpath.split("?",1)+[""])[:2] if "?" in fullpath else (fullpath, "")
        params = parse_qs(qs)
        headers = parse_headers(data)
        now_ms = time.ticks_ms()

        def require_auth_or_deny():
            ok, status, blocked = check_basic_auth(headers, now_ms)
            if ok:
                return True
            if status.startswith("429"):
                http_response(conn, "429 Too Many Requests",
                              body="Too Many Requests. Riprova tra {}s.".format(AUTH["BLOCK_SECONDS"]))
            else:
                http_response(conn, "401 Unauthorized",
                              extra_headers=['WWW-Authenticate: Basic realm="PicoUptime"'],
                              body="Auth required.")
            return False

        # /health (token pubblico o protetta)
        if path == "/health":
            token_ok = False
            tok = AUTH["HEALTH_PUBLIC_TOKEN"]
            if tok:
                token_ok = (params.get("token","") == tok)
            if not token_ok:
                if not require_auth_or_deny():
                    conn.close(); return targets, states
            hd = health_dict(uptime_start_ms, targets, states)
            if params.get("json","") == "1":
                body = json.dumps(hd)
                http_response(conn, "200 OK", "application/json", body)
            else:
                body = """<!doctype html><html><head><meta charset="utf-8"><title>Health</title>
<style>body{font-family:system-ui;margin:24px}</style></head><body>
<h2>✅ Health</h2>
<ul>
  <li>Uptime: {uptime}s</li>
  <li>IP: {ip}</li>
  <li>HTTP port: {port}</li>
  <li>Targets: {targets} (UP {up} / DOWN {down} / UNKNOWN {unk})</li>
  <li>Heap free: {heap} bytes</li>
  <li>Interval: {interval}s</li>
</ul>
<p><a href="/">← Torna</a></p>
</body></html>""".format(
    uptime=hd["uptime_s"], ip=hd["ip"], port=hd["http_port"],
    targets=hd["targets"], up=hd["up"], down=hd["down"], unk=hd["unknown"],
    heap=hd["heap_free"], interval=hd["interval_s"]
)
                http_response(conn, "200 OK", "text/html; charset=utf-8", body)
            conn.close(); return targets, states

        # Tutto il resto protetto
        if not require_auth_or_deny():
            conn.close(); return targets, states

        flash = ""
        if path == "/":
            http_response(conn, body=render_page(targets, states, flash))
        elif path == "/add":
            name = params.get("name","").strip() or "target"
            mode = params.get("mode","http")
            if mode == "http":
                url = params.get("url","").strip()
                if url:
                    targets.append({"name": name, "mode": "http", "url": url})
                    save_targets(targets)
                    states.append({"status": None, "oks": 0, "fails": 0, "last_code": None})
                    flash = "Aggiunto target HTTP."
                else:
                    flash = "URL mancante."
            elif mode == "tcp":
                host = params.get("host","").strip()
                port = int(params.get("port","0") or "0")
                if host and port > 0:
                    targets.append({"name": name, "mode": "tcp", "host": host, "port": port})
                    save_targets(targets)
                    states.append({"status": None, "oks": 0, "fails": 0, "last_code": None})
                    flash = "Aggiunto target TCP."
                else:
                    flash = "Host/Porta mancanti."
            elif mode == "ping":
                host = params.get("host","").strip()
                if host:
                    targets.append({"name": name, "mode": "ping", "host": host})
                    save_targets(targets)
                    states.append({"status": None, "oks": 0, "fails": 0, "last_code": None})
                    flash = "Aggiunto target PING."
                else:
                    flash = "Host mancante."
            else:
                flash = "Modo non valido."
            http_response(conn, body=render_page(targets, states, flash))
        elif path == "/set":
            # Lettura parametri e validazione
            try:
                ci = int(params.get("ci","") or CONFIG["CHECK_INTERVAL"])
                up = int(params.get("up","") or CONFIG["UP_THRESHOLD"])
                dn = int(params.get("dn","") or CONFIG["DOWN_THRESHOLD"])
            except:
                ci, up, dn = CONFIG["CHECK_INTERVAL"], CONFIG["UP_THRESHOLD"], CONFIG["DOWN_THRESHOLD"]

            ci = max(5, min(ci, 3600))
            up = max(1, min(up, 10))
            dn = max(1, min(dn, 10))

            CONFIG["CHECK_INTERVAL"] = ci
            CONFIG["UP_THRESHOLD"]   = up
            CONFIG["DOWN_THRESHOLD"] = dn
            save_runtime_config()

            flash = "Impostazioni salvate: intervallo {}s, soglie UP={}, DOWN={}.".format(ci, up, dn)
            http_response(conn, body=render_page(targets, states, flash))
        elif path == "/del":
            i = int(params.get("i","-1") or "-1")
            if 0 <= i < len(targets):
                targets.pop(i); save_targets(targets)
                states.pop(i)
                flash = "Target eliminato."
            else:
                flash = "Indice non valido."
            http_response(conn, body=render_page(targets, states, flash))
        elif path == "/test":
            i = int(params.get("i","-1") or "-1")
            if 0 <= i < len(targets):
                t = targets[i]
                ok = False; code = None
                if t["mode"] == "http":
                    ok, code = check_http(t["url"])
                elif t["mode"] == "tcp":
                    ok = check_tcp(t["host"], t["port"])
                else:  # ping
                    ok, code = check_ping(t["host"])
                if i < len(states): states[i]["last_code"] = code
                if t["mode"] == "ping":
                    flash = ("UP ✅" if ok else "DOWN ❌") + ("" if code is None else " ({} ms)".format(code))
                else:
                    flash = ("UP ✅" if ok else "DOWN ❌") + ("" if code is None else " (HTTP {})".format(code))
            else:
                flash = "Indice non valido."
            http_response(conn, body=render_page(targets, states, flash))
        else:
            http_response(conn, "404 Not Found", body="Not Found")

        conn.close()
        return targets, states

    except Exception as e:
        print("[HTTP] serve error:", repr(e))
        try:
            SERVER_SOCK.close()
        except:
            pass
        SERVER_SOCK = None
        gc.collect()
        time.sleep(0.1)
        return targets, states

# =======================
# ===== MAIN LOOP =======
# =======================
def main():
    print("[PicoUptime] starting...")
    while not wifi_connect(CONFIG["WIFI_SSID"], CONFIG["WIFI_PASSWORD"]):
        time.sleep(3)
    
    load_runtime_config()  # <-- carica config (se presente)

    targets = load_targets()
    states = [{"status": None, "oks": 0, "fails": 0, "last_code": None} for _ in targets]

    last_check_ms = time.ticks_ms()
    interval_ms = CONFIG["CHECK_INTERVAL"] * 1000
    uptime_start_ms = time.ticks_ms()
    wifi_fail_count = 0   # contatore fail Wi-Fi

    while True:
        wlan = network.WLAN(network.STA_IF)
        if not wlan.isconnected():
            wifi_fail_count += 1
            print("[WiFi] lost, retry", wifi_fail_count)
            wifi_connect(CONFIG["WIFI_SSID"], CONFIG["WIFI_PASSWORD"])
            if wifi_fail_count > 10:   # dopo 10 tentativi consecutivi falliti
                print("[WiFi] too many fails, rebooting...")
                notify("⚠️ Riavvio automatico: Wi-Fi non disponibile.")
                time.sleep(2)
                machine.reset()
        else:
            wifi_fail_count = 0  # reset se torna online

        targets, states = serve_once(targets, states, uptime_start_ms)

        now = time.ticks_ms()
        interval_ms = CONFIG["CHECK_INTERVAL"] * 1000  # <-- ricalcola ad ogni giro
        if time.ticks_diff(now, last_check_ms) >= interval_ms:
            last_check_ms = now
            if len(states) != len(targets):
                states = [{"status": None, "oks": 0, "fails": 0, "last_code": None} for _ in targets]

            for i, t in enumerate(targets):
                try:
                    if t["mode"] == "http":
                        ok, code = check_http(t["url"]); states[i]["last_code"] = code
                    elif t["mode"] == "tcp":
                        ok = check_tcp(t["host"], t["port"]); states[i]["last_code"] = None
                    else:  # ping
                        ok, rtt = check_ping(t["host"]); states[i]["last_code"] = rtt
                except:
                    ok = False; states[i]["last_code"] = None

                prev = states[i]["status"]
                if ok:
                    states[i]["oks"] += 1; states[i]["fails"] = 0
                    if prev is None:
                        if states[i]["oks"] >= CONFIG["UP_THRESHOLD"]:
                            states[i]["status"] = True
                        continue
                    if prev is False and states[i]["oks"] >= CONFIG["UP_THRESHOLD"]:
                        states[i]["status"] = True
                        # --- transizione DOWN -> UP ---
                        notify("✅ {} è ONLINE".format(t.get("name", "servizio")))
                else:
                    states[i]["fails"] += 1; states[i]["oks"] = 0
                    if prev is None:
                        if states[i]["fails"] >= CONFIG["DOWN_THRESHOLD"]:
                            states[i]["status"] = False
                        continue
                    if prev is True and states[i]["fails"] >= CONFIG["DOWN_THRESHOLD"]:
                        states[i]["status"] = False
                        # --- transizione UP -> DOWN ---
                        notify("❌ {} è OFFLINE".format(t.get("name", "servizio")))

        time.sleep(0.05)

try:
    main()
except Exception as e:
    try:
        notify("⚠️ Monitor Pico: eccezione inattesa, riavvio…")
    except:
        pass
    time.sleep(2)
    machine.reset()
