# 🧭 Pico Uptime — MicroPython Uptime Monitor

**Pico Uptime** è un mini monitor di disponibilità (uptime monitor) scritto interamente in **MicroPython**, progettato per girare su un **Raspberry Pi Pico W**.  
Controlla automaticamente host e servizi in modalità **HTTP**, **TCP** o **PING (ICMP)**, mostra lo stato in una **Web UI con login protetto** e invia notifiche **Telegram** solo quando cambia lo stato (UP/DOWN).  
Nessun cloud, nessun server esterno: tutto gira *on-board* sul Pico W. 

Il tutto nasce dal mitico https://github.com/louislam/uptime-kuma

---

## 🚀 Caratteristiche

- ✅ Monitor multiprotocollo: **HTTP / TCP / PING (ICMP)**
- 🔔 Notifiche Telegram solo su variazioni di stato
- 🔐 Web dashboard con **Basic Auth** e pagina **/health**
- 💾 Configurazione dinamica via web (aggiungi, elimina o testa target)
- 🧠 Autoprotezione: se il Wi-Fi cade per troppo tempo, il Pico si **riavvia automaticamente**
- 💡 LED di stato integrato (lampeggio durante la connessione Wi-Fi)
- 🧱 Tutto in un solo file `main.py`, senza librerie esterne

---

## 🧰 Requisiti Hardware e Software

### Hardware
- [Raspberry Pi Pico W](https://www.raspberrypi.com/products/raspberry-pi-pico-w/)  
- Connessione Wi-Fi attiva  
- Cavo micro-USB per alimentazione e flash del firmware  

### Software
- [Thonny IDE](https://thonny.org/) (consigliato per caricare i file)
- **Firmware MicroPython per Pico W** → scaricalo da  
  👉 [https://micropython.org/download/rp2-pico-w/](https://micropython.org/download/rp2-pico-w/)  

🛠️ Note tecniche

- Testato su MicroPython v1.26.1
- Nessuna libreria esterna richiesta
- Supporta HTTPS (tramite ssl.wrap_socket)
- Tutti i pacchetti TCP/ICMP gestiti manualmente via socket
- Tempo di polling configurabile (CHECK_INTERVAL)

📜 Licenza

Distribuito sotto licenza MIT — puoi modificare, ridistribuire e utilizzare liberamente, citando l’autore originale.

❤️ Autore

Progetto creato con passione da Luke
