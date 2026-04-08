# protonwg-sentinel

> A terminal-based live monitor for WireGuard + ProtonVPN connections on Linux.  
> Verifies tunnel health, IP/location, ASN ownership, DNS leak status, routing,
> and kill-switch presence — all from a single Python script with no third-party
> dependencies.

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-6.0-brightgreen)

---

## What it checks

| Check | What it tells you |
|---|---|
| **WireGuard handshake** | Is the tunnel alive? When was the last handshake? |
| **WireGuard config validation** | AllowedIPs (full-tunnel 0.0.0.0/0), keepalive, listening port |
| **Public IPv4 + IPv6** | Your actual exit IPs on the internet |
| **IP geolocation** | Country, city, timezone — from 3 independent sources |
| **Exit location** | City and country shown in compact status view |
| **ASN / ISP** | Who owns the exit IP block |
| **ProtonVPN ownership** | Is the exit IP on Proton-owned (✓) or Proton-partnered (⚙) infrastructure? |
| **DNS leak — standard** | Which resolvers did ipleak.net see? |
| **DNS leak — advanced** | bash.ws engine (same backend as dnsleaktest.com Extended Test) |
| **DNS resolver classification** | Proton internal / known-safe public / possible leak |
| **ProtonVPN internal DNS** | Recognises 10.x.x.x tunnel resolvers as safe (not a false-positive leak) |
| **Default route** | Does traffic actually default through the VPN interface? |
| **Kill switch** | Are iptables/nftables DROP rules active to block cleartext fallback? |
| **Endpoint latency** | Round-trip ping to the WireGuard server endpoint |
| **System info** | Hostname, OS, kernel, architecture |
| **Connection logging** | JSON log of every check at `~/.local/share/protonwg-sentinel/connections.json` |

---

## Requirements

```bash
# Python 3.8+ (no pip packages needed — stdlib only)
python3 --version

# WireGuard tools
sudo apt install wireguard-tools     # Debian/Ubuntu/Kali

# Optional but recommended
sudo apt install dnsutils iputils-ping   # for dig + ping
sudo apt install iptables                # for kill-switch check
```

The script uses only Python standard library modules:  
`ipaddress`, `json`, `os`, `platform`, `random`, `re`, `shutil`, `signal`,  
`socket`, `string`, `subprocess`, `sys`, `termios`, `threading`, `time`,  
`tty`, `unicodedata`, `urllib.request`, `datetime`

---

## Installation

```bash
git clone https://github.com/RevShellX/protonwg-sentinel.git
cd protonwg-sentinel
```

Edit the configuration block at the top of `protonwg_sentinel.py`:

```python
INTERFACE        = "Sweden"   # Your WireGuard interface name (check: sudo wg show)
STALE_WARN_SEC   = 150        # Warn if handshake older than this (seconds)
STALE_DEAD_SEC   = 300        # Treat as dead beyond this
COMPACT_INTERVAL = 5          # Seconds between compact status refreshes
FULL_INTERVAL    = 60         # Seconds between automatic full re-checks
```

Find your interface name with:
```bash
sudo wg show
# or
ip link show | grep -i wg
```

---

## Usage

```bash
sudo python3 protonwg_sentinel.py
```

Root (or `sudo`) is required to call `wg show` for handshake data and to read
iptables rules for kill-switch detection.

Press `Ctrl-C` to stop.  Press `Enter` to force an immediate full re-check.

---

## Understanding the output

### ProtonVPN ASN classification

The script uses a three-tier system to classify exit IPs:

| Symbol | Meaning |
|---|---|
| ✅ Green (✓) | IP block **owned directly by Proton AG** |
| 🟠 Orange (⚙) | **Known ProtonVPN datacenter partner** — leased hardware, Proton-controlled |
| ❌ Red | Not recognised as Proton or a known partner |

**Orange/⚙ is not a warning.** The majority of ProtonVPN's servers run on partner
datacenters (primarily M247). Your traffic is still encrypted end-to-end by
WireGuard regardless of who owns the physical rack.

### Complete ASN database (v6.0)

#### Official Proton AG ASNs (✓ owned)

| ASN | Description |
|---|---|
| **AS209103** | Proton AG — primary (Secure Core, Switzerland) |
| **AS51396** | Proton AG — secondary |
| **AS62371** | Proton AG — main / upstream Switzerland |
| **AS199218** | Proton AG — ProtonVPN-2 (newer infrastructure) |
| **AS208172** | Proton AG — expansion network |
| **AS207951** | Proton AG — additional allocation |

#### Contracted Infrastructure Partners (⚙ partner)

Sources: [Netify.ai](https://www.netify.ai/resources/vpns/proton-vpn) + [bgp.he.net](https://bgp.he.net) + [bgp.tools](https://bgp.tools)

| ASN | Provider | Region |
|---|---|---|
| **AS9009** | M247 Europe SRL | EU + US (primary) |
| **AS51332** | M247 Ltd | Secondary allocation |
| **AS60068** | Datacamp Ltd / CDN77 | Europe & global CDN |
| **AS212238** | Datacamp Ltd | Additional capacity |
| **AS46562** | Performive LLC | North America |
| **AS63023** | GTHost | US (Phoenix) |
| **AS49981** | Worldstream B.V. | Netherlands (Amsterdam) |
| **AS24875** | NovoServe B.V. | Netherlands (Amsterdam) |
| **AS35432** | Latitude.sh | Hosting partner |
| **AS262287** | Latitude.sh LTDA | South America |
| **AS396356** | Latitude.sh LLC | South America / US |
| **AS1257** | Tele2 AB | Estonia / Scandinavia |
| **AS8473** | Bahnhof AB | Sweden |
| **AS202053** | Creanova Oy | Finland |
| **AS20473** | Choopa LLC / Vultr | Global hosting |
| **AS13335** | Cloudflare Inc. | Upstream peer / CDN |
| **AS8452** | Telecom Egypt | Middle East |
| **AS16247** | Akamai / Linode | Global content delivery |

### DNS resolver classification

Each DNS resolver detected by the leak tests is tagged:

| Tag | Meaning |
|---|---|
| `← ProtonVPN internal tunnel DNS ✓` | 10.x.x.x / RFC1918 — Proton's internal resolver, pushed into the WireGuard tunnel. **Expected and safe.** |
| `← known-safe public DNS ✓` | Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) — privacy-respecting resolvers, acceptable inside the VPN tunnel |
| `← Proton network ✓` | Exit IP is via a Proton-owned or partner ASN |
| `← Proton DNS ✓` | ISP string contains "proton" keyword |
| `← possible leak — not Proton DNS` | Resolver is unrecognised — verify manually |

### DNS resolvers showing 10.x.x.x

If your DNS leak test shows resolvers like `10.12.5.13` / `10.12.5.14`, this is
**correct and expected**. ProtonVPN pushes private-range resolvers into the
WireGuard tunnel interface. They are Proton's own internal DNS servers, reachable
only inside the encrypted tunnel. The script recognises this and reports them as
safe.

### WireGuard configuration validation

The script reads `wg show <interface>` output to validate:

- **AllowedIPs 0.0.0.0/0** — confirms full-tunnel routing (all traffic goes via VPN)
- **Persistent keepalive** — shows the keepalive interval (important for NAT traversal)
- **Listening port** — the UDP port the WireGuard daemon is using

If AllowedIPs does not include `0.0.0.0/0`, the script warns that split-tunnel
mode may be active and some traffic could bypass the VPN.

### Kill switch

ProtonVPN's Linux app (and manual iptables setups) add `DROP` rules to the
`OUTPUT` chain that block all traffic on non-VPN interfaces. If the kill switch
is off and your WireGuard tunnel drops, your traffic may briefly exit via your
real IP. The script reports whether these rules are present.

### Connection logging

Every full check is appended to a JSON log file:

```
~/.local/share/protonwg-sentinel/connections.json
```

Each record contains: timestamp (UTC), ASN, provider name, proton_level, IPv4,
IPv6, exit location, WireGuard status, and DNS check results. The log keeps the
last 1 000 records automatically.

---

## Data sources

### IP geolocation (3 independent sources)

| Source | URL | Notes |
|---|---|---|
| ip-api.com | https://ip-api.com | Country, region, city, ISP, ASN |
| ipinfo.io | https://ipinfo.io | Org, hostname, timezone |
| ipwho.is | https://ipwho.is | Continent, coordinates, connection info |

### DNS leak testing

| Source | URL | Notes |
|---|---|---|
| ipleak.net API | https://api.ipleak.net/dnsdetect/ | Standard DNS leak check |
| bash.ws | https://bash.ws | Advanced leak check — the actual backend behind dnsleaktest.com |
| dnsleaktest.com | https://www.dnsleaktest.com | Manual verification (Extended Test) |

### ASN / ProtonVPN infrastructure

| Source | URL | Purpose |
|---|---|---|
| ipinfo.io/AS209103 | https://ipinfo.io/AS209103 | Proton AG primary ASN |
| ipinfo.io/AS51396 | https://ipinfo.io/AS51396 | Proton AG secondary ASN |
| bgp.he.net | https://bgp.he.net | BGP routing verification |
| bgp.tools | https://bgp.tools | BGP intelligence |
| PeeringDB | https://www.peeringdb.com | ASN peering data |
| Netify VPN map | https://www.netify.ai/resources/vpns/proton-vpn | Partner datacenter list |

### Public IP detection

| Source | URL |
|---|---|
| ipify.org (IPv4) | https://api.ipify.org?format=json |
| ipify.org (IPv6) | https://api6.ipify.org?format=json |

---

## Security notes

- The script makes outbound HTTP/HTTPS requests to third-party APIs.
  All requests travel through your VPN tunnel (that is the point).
- Connection logs are written to `~/.local/share/protonwg-sentinel/connections.json`.
  They contain exit IPs and ASN info — treat them as sensitive if you share the file.
- `sudo` is used only for `wg show` and `iptables -L` — both read-only operations.
- The bash.ws DNS leak test works by resolving random subdomains server-side;
  the random session ID is generated fresh each run and is not linked to your identity.

---

## Tested on

| OS | Kernel | WireGuard | Python |
|---|---|---|---|
| Kali Linux 2025.x | 6.12+ kali-amd64 | wg-tools 1.0.20210914 | 3.13 |
| Ubuntu 24.04 LTS | 6.8 | wg-tools 1.0.20210914 | 3.12 |

---

## Contributing

Issues and pull requests welcome. Some ideas for further development:

- **Phase 2** — WebRTC leak detection (requires browser hook or headless Chromium)
- **Phase 2** — IPv6 route verification (confirm IPv6 also exits via VPN)
- **Phase 2** — WireGuard MTU / packet fragmentation check
- **Phase 3** — Automated ASN database updates from bgp.tools / PeeringDB
- **Phase 3** — Alert / notification system (ntfy, Pushover, Telegram, Discord)
- **Phase 3** — Systemd service mode (run headless, alert on state change)
- **Phase 4** — Multi-protocol support (OpenVPN, IKEv2/IPSec detection)
- **Phase 4** — Threat intelligence integration (cross-reference IPs against blocklists)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This tool is for personal verification and educational use. It relies on
third-party APIs that may change or become unavailable. Always cross-check with
[dnsleaktest.com](https://www.dnsleaktest.com) (Extended Test) and
[ipleak.net](https://ipleak.net) manually for critical security assessments.
