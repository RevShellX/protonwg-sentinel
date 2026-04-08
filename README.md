# protonwg-sentinel

> A terminal-based live monitor for WireGuard + ProtonVPN connections on Linux.  
> Verifies tunnel health, IP/location, ASN ownership, DNS leak status, routing,
> and kill-switch presence — all from a single Python script with no third-party
> dependencies.

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it checks

| Check | What it tells you |
|---|---|
| **WireGuard handshake** | Is the tunnel alive? When was the last handshake? |
| **Public IPv4 + IPv6** | Your actual exit IPs on the internet |
| **IP geolocation** | Country, city, timezone — from 3 independent sources |
| **ASN / ISP** | Who owns the exit IP block |
| **ProtonVPN ownership** | Is the exit IP on Proton-owned or Proton-partnered infrastructure? |
| **DNS leak — standard** | Which resolvers did ipleak.net see? |
| **DNS leak — advanced** | bash.ws engine (same backend as dnsleaktest.com Extended Test) |
| **ProtonVPN internal DNS** | Recognises 10.x.x.x tunnel resolvers as safe (not a false-positive leak) |
| **Default route** | Does traffic actually default through the VPN interface? |
| **Kill switch** | Are iptables/nftables DROP rules active to block cleartext fallback? |
| **Endpoint latency** | Round-trip ping to the WireGuard server endpoint |
| **System info** | Hostname, OS, kernel, architecture |

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
`json`, `platform`, `random`, `signal`, `socket`, `string`, `subprocess`,  
`sys`, `time`, `urllib.request`, `datetime`, `ipaddress`

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/protonwg-sentinel.git
cd protonwg-sentinel
```

Edit the configuration block at the top of `check_wg.py`:

```python
INTERFACE      = "Sweden"   # Your WireGuard interface name (check: sudo wg show)
STALE_WARN_SEC = 150        # Warn if handshake older than this (seconds)
STALE_DEAD_SEC = 300        # Treat as dead beyond this
POLL_INTERVAL  = 30         # Seconds between screen refreshes
IP_CACHE_TICKS = 2          # Re-fetch network data every N ticks
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
sudo python3 check_wg.py
```

Root (or `sudo`) is required to call `wg show` for handshake data and to read
iptables rules for kill-switch detection.

Press `Ctrl-C` to stop.

---

## Understanding the output

### ProtonVPN ASN classification

The script uses a three-tier system to classify exit IPs:

| Symbol | Meaning |
|---|---|
| ✅ Green | IP block **owned directly by Proton AG** |
| 🟠 Orange | **Known ProtonVPN datacenter partner** — leased hardware, Proton-controlled |
| ❌ Red | Not recognised as Proton or a known partner |

**Orange is not a warning.** The majority of ProtonVPN's servers run on partner
datacenters (primarily M247). Your traffic is still encrypted end-to-end by
WireGuard regardless of who owns the physical rack.

### DNS resolvers showing 10.x.x.x

If your DNS leak test shows resolvers like `10.12.5.13` / `10.12.5.14`, this is
**correct and expected**. ProtonVPN pushes private-range resolvers into the
WireGuard tunnel interface. They are Proton's own internal DNS servers, reachable
only inside the encrypted tunnel. The script recognises this and reports them as
safe.

### Kill switch

ProtonVPN's Linux app (and manual iptables setups) add `DROP` rules to the
`OUTPUT` chain that block all traffic on non-VPN interfaces. If the kill switch
is off and your WireGuard tunnel drops, your traffic may briefly exit via your
real IP. The script reports whether these rules are present.

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
- No data is stored locally beyond the current terminal session.
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

- MTU / packet fragmentation check
- WebRTC leak detection (would require a browser hook or headless Chromium)
- IPv6 route verification (confirm IPv6 also exits via VPN)
- Persistent logging to JSON/CSV
- Alerting via ntfy / Pushover / email on tunnel drop
- Systemd service mode (run headless, alert on state change)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This tool is for personal verification and educational use. It relies on
third-party APIs that may change or become unavailable. Always cross-check with
[dnsleaktest.com](https://www.dnsleaktest.com) (Extended Test) and
[ipleak.net](https://ipleak.net) manually for critical security assessments.
