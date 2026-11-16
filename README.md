# NetScan

**A local network scanner for macOS with a clean web interface. Zero dependencies, nothing saved to disk.**

*Italiano: [vai alla sezione italiana](#italiano)*

NetScan finds every device on your LAN and shows its IP address, MAC address, vendor and name, in a sortable, searchable table that opens in your browser. It is a single Python file that uses only the standard library, so there is nothing to install.

## Features

- **Automatic network detection**: finds the active interface, IP, subnet and gateway on its own, even with a VPN running
- **Interface selector**: pick Wi-Fi or Ethernet when both are connected
- **Device list**: IPv4 address (clickable, opens the device's web page like a router does), MAC address, vendor, hostname
- **Hostname discovery** via reverse DNS, mDNS/Bonjour and NetBIOS, queried in parallel
- **Vendor lookup** from the IEEE registries (MA-L, MA-M and MA-S), downloaded into memory at startup
- **Ping indicator**: green/red dot with latency (red means the device is on the network but does not answer ping, e.g. firewall or phone in standby)
- **Light/dark theme** switch, search, column sorting, optional auto-refresh every 60 s
- **Nothing is written to disk**: no files, no cache, no history, no saved settings. The list is erased on every manual scan, and the program quits by itself when you close the browser tab

## Requirements

- macOS
- Python 3.8 or newer (the `python3` that comes with the Xcode Command Line Tools is fine)

NetScan relies on macOS system tools (`ifconfig`, `route`, `arp`, `ping`, `networksetup`), so it does not run on Linux or Windows.

## Usage

```bash
python3 netscan.py
```

Your browser opens at `http://127.0.0.1:8765` and the first scan starts automatically. Close the browser tab to quit.

On recent macOS versions the first run may ask for **Local Network** permission: allow it, otherwise the scan will find little or nothing.

### Double-click launcher

Keep `NetScan.command` in the same folder as `netscan.py` (you can move both anywhere). Make it executable once:

```bash
chmod +x NetScan.command
xattr -d com.apple.quarantine NetScan.command netscan.py 2>/dev/null
```

After that, double-click `NetScan.command` to start.

## How it works

1. Detects the active network interface and its subnet (a /24 at most).
2. Pings every address of the subnet in parallel, which also fills the ARP table.
3. Reads the ARP table to get IP and MAC pairs, including devices that do not answer ping.
4. Resolves names with DNS, mDNS and NetBIOS in parallel, and looks up the vendor from the MAC.
5. Serves the results to a small web page on `127.0.0.1` only.

## Privacy

NetScan writes nothing to disk and keeps results only in memory until it quits. Things outside its control may still leave traces, such as your shell history (if you start it from Terminal), your browser history (the `127.0.0.1:8765` address, not the device list) and the system ARP cache in RAM.

On startup it downloads the public IEEE vendor lists into memory. If you are offline the scan still works, only the vendor column stays empty.

The local server accepts requests only from its own page (it checks the `Host` and `Origin` headers), so other websites cannot read the results or start scans.

## Limitations

- IPv4 only
- Randomized (private) MAC addresses used by recent phones are shown as "MAC privato/casuale" without a vendor
- Some devices expose no hostname at all
- A device in deep sleep may not appear on the first scan: scan again
- The interface is currently in Italian

## Responsible use

Scan only networks you own or have permission to scan.

## License

MIT, see [LICENSE](LICENSE).

---

## Italiano

**NetScan** è uno scanner di rete locale per macOS con interfaccia web. Un solo file Python, nessuna dipendenza, e non salva nulla sul disco.

Mostra tutti i dispositivi della LAN con indirizzo IP (cliccabile), MAC, produttore, nome e pallino ping verde/rosso. Rileva da solo la rete attiva, permette di scegliere tra Wi-Fi ed Ethernet, ha tema chiaro/scuro, ricerca, ordinamento e auto-refresh.

**Avvio**

```bash
python3 netscan.py
```

Si apre il browser su `http://127.0.0.1:8765` e parte la scansione. Chiudendo la scheda del browser il programma si chiude da solo.

**Doppio clic**: tieni `NetScan.command` nella stessa cartella di `netscan.py`, poi esegui una volta `chmod +x NetScan.command`. Da quel momento basta il doppio clic.

**Privacy**: nessun file, cache o cronologia viene scritto; la lista vive solo in memoria. Il pallino rosso non significa offline: il dispositivo è presente in rete ma non risponde al ping (firewall o standby).

**Uso responsabile**: scansiona solo reti tue o per cui hai il permesso.
