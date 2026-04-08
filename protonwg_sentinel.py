#!/usr/bin/env python3
"""
protonwg-sentinel  v6.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WireGuard + ProtonVPN connection monitor — stdlib only, no pip needed

Behaviour:
  • On startup  : full detailed report (all checks, all sources)
  • After that  : compact live status — green = connected, red = down
  • Press ENTER : force immediate full re-check and detailed report
  • Ctrl-C      : quit

Checks:
  • WireGuard tunnel handshake freshness
  • WireGuard configuration validation (AllowedIPs, keepalive, listening port)
  • Public IPv4 and IPv6 exit addresses
  • Full location + ISP info  (3 independent sources)
  • ProtonVPN ASN ownership   (✓ Proton-owned / ⚙ partner / ❌ unknown)
  • DNS leak — standard (ipleak.net) + advanced (bash.ws / dnsleaktest engine)
  • DNS resolver classification (Proton internal / known-safe / possible leak)
  • ProtonVPN internal resolver recognition  (10.x.x.x = safe, not a false-positive leak)
  • Default route sanity  (traffic actually goes through VPN interface)
  • Kill-switch detection  (iptables / nftables DROP rules)
  • WireGuard endpoint ping latency
  • System identity: hostname, OS, kernel, architecture
  • Historical connection logging  (~/.local/share/protonwg-sentinel/connections.json)

ASN / infrastructure sources:
  • ProtonVPN server map  : https://www.netify.ai/resources/vpns/proton-vpn
  • ASN verified          : https://bgp.he.net  +  https://ipinfo.io
  • Proton-owned ASNs     : https://ipinfo.io/AS209103 | https://ipinfo.io/AS51396
  • BGP intelligence      : https://bgp.tools  |  https://www.peeringdb.com

GitHub: https://github.com/RevShellX/protonwg-sentinel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import ipaddress, json, os, platform, random, re, shutil, signal, socket
import string, subprocess, sys, termios, threading, time, tty, unicodedata
import urllib.request
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────────
INTERFACE        = "Sweden"   # WireGuard interface name  (check: sudo wg show)
STALE_WARN_SEC   = 150        # warn if handshake older than this (seconds)
STALE_DEAD_SEC   = 300        # treat tunnel as dead beyond this
COMPACT_INTERVAL = 5          # seconds between compact status refreshes
FULL_INTERVAL    = 60         # seconds between automatic full re-checks
HTTP_TIMEOUT     = 6
DNS_TIMEOUT      = 8
W                = 72         # display width (fallback when terminal width unavailable)
MIN_WIDTH        = 72         # minimum terminal width used by _tw()
MAX_WIDTH        = 120        # maximum terminal width used by _tw()
TERM_MARGIN      = 2          # columns to subtract from raw terminal width in _tw()
BOX_PADDING      = 2          # spaces between box border and content in _box_row()
LOG_DIR          = os.path.expanduser("~/.local/share/protonwg-sentinel")
LOG_FILE         = os.path.join(LOG_DIR, "connections.json")
# ──────────────────────────────────────────────────────────────────────────────

# ── ProtonVPN ASN database ─────────────────────────────────────────────────────

# ✅ Proton AG — IP blocks owned directly by Proton AG  (✓ official)
# Sources: https://ipinfo.io/AS209103  |  https://bgp.tools  |  https://www.netify.ai/resources/vpns/proton-vpn
PROTON_OWNED_ASN = {
    "AS209103",   # Proton AG  (primary — Secure Core, Switzerland)
    "AS51396",    # Proton AG  (secondary)
    "AS62371",    # Proton AG  (main / upstream Switzerland)
    "AS199218",   # Proton AG  (ProtonVPN-2 — newer infrastructure)
    "AS208172",   # Proton AG  (expansion network)
    "AS207951",   # Proton AG  (additional allocation)
}

# ⚙  PARTNER — contracted datacenter partners (leased, Proton-controlled)  (⚙ partner)
# Sources: https://www.netify.ai/resources/vpns/proton-vpn  +  bgp.he.net  +  bgp.tools
# NOTE: partner does NOT mean unsafe — traffic is WireGuard-encrypted end-to-end
PROTON_PARTNER_ASN = {
    # M247 — most common ProtonVPN exit provider
    "AS9009",    # M247 Europe SRL        — EU + US (primary)
    "AS51332",   # M247 Ltd               — secondary allocation
    # Datacamp / CDN77
    "AS60068",   # Datacamp Ltd / CDN77   — Europe & global CDN
    "AS212238",  # Datacamp Ltd           — additional capacity
    # Performive / TSS
    "AS46562",   # Performive LLC         — North America
    # GTHost
    "AS63023",   # GTHost                 — US (Phoenix)
    # Worldstream / NovoServe
    "AS49981",   # Worldstream B.V.       — Netherlands (Amsterdam)
    "AS24875",   # NovoServe B.V.         — Netherlands (Amsterdam)
    # Latitude.sh (formerly Maxihost)
    "AS35432",   # Latitude.sh            — hosting partner
    "AS262287",  # Latitude.sh LTDA       — South America
    "AS396356",  # Latitude.sh LLC        — South America / US
    # Tele2 / Bahnhof — Scandinavia
    "AS1257",    # Tele2 AB               — Estonia / Scandinavia
    "AS8473",    # Bahnhof AB             — Sweden
    # Creanova — Finland
    "AS202053",  # Creanova Oy            — Finland
    # Choopa / Vultr — global
    "AS20473",   # Choopa LLC / Vultr     — global hosting
    # Cloudflare — upstream peer
    "AS13335",   # Cloudflare Inc.        — upstream peer / CDN
    # Telecom Egypt — Middle East
    "AS8452",    # Telecom Egypt          — Middle East
    # Akamai / Linode
    "AS16247",   # Akamai / Linode        — global content delivery
}

PROTON_DNS_KW = {"proton", "protonvpn", "proton.me", "proton.ch"}

# ProtonVPN pushes private-range resolvers into the WireGuard tunnel.
# e.g. 10.12.5.13 / 10.12.5.14 — Proton internal DNS, NOT a leak.
PROTON_INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]

# Human-readable labels for every known ASN
# Format: ASN -> (short_name, trust_indicator)   ✓ = Proton-owned   ⚙ = partner
ASN_LABELS = {
    # Official Proton AG
    "AS209103": ("Proton AG",        "✓"),
    "AS51396":  ("Proton AG",        "✓"),
    "AS62371":  ("Proton AG",        "✓"),
    "AS199218": ("Proton AG",        "✓"),
    "AS208172": ("Proton AG",        "✓"),
    "AS207951": ("Proton AG",        "✓"),
    # Contracted partners
    "AS9009":   ("M247 Europe",      "⚙"),
    "AS51332":  ("M247 Ltd",         "⚙"),
    "AS60068":  ("Datacamp/CDN77",   "⚙"),
    "AS212238": ("Datacamp Ltd",     "⚙"),
    "AS46562":  ("Performive",       "⚙"),
    "AS63023":  ("GTHost",           "⚙"),
    "AS49981":  ("Worldstream",      "⚙"),
    "AS24875":  ("NovoServe",        "⚙"),
    "AS35432":  ("Latitude.sh",      "⚙"),
    "AS262287": ("Latitude.sh",      "⚙"),
    "AS396356": ("Latitude.sh",      "⚙"),
    "AS1257":   ("Tele2",            "⚙"),
    "AS8473":   ("Bahnhof",          "⚙"),
    "AS202053": ("Creanova",         "⚙"),
    "AS20473":  ("Choopa/Vultr",     "⚙"),
    "AS13335":  ("Cloudflare",       "⚙"),
    "AS8452":   ("Telecom Egypt",    "⚙"),
    "AS16247":  ("Akamai/Linode",    "⚙"),
}

# Well-known privacy-respecting public DNS resolvers (safe when inside Proton tunnel)
KNOWN_SAFE_DNS_IPS = {
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS  (AS13335 — Proton partner)
    "9.9.9.9", "149.112.112.112",    # Quad9  (privacy-focused)
}

# ── ANSI ───────────────────────────────────────────────────────────────────────
RST     = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
ITALIC  = "\033[3m"
RED     = "\033[91m"
ORANGE  = "\033[38;5;208m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
PURPLE  = "\033[38;5;141m"
TEAL    = "\033[38;5;43m"
GOLD    = "\033[38;5;220m"
BG_BLK  = "\033[40m"
BLACK   = "\033[30m"

# ── Terminal helpers ────────────────────────────────────────────────────────────
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mKJH]')


def _vis(s):
    """Visible column width of *s*, ignoring ANSI codes (handles wide/emoji chars)."""
    clean = _ANSI_RE.sub('', s)
    return sum(
        2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
        for c in clean
    )


def _tw():
    """Terminal width, clamped to MIN_WIDTH–MAX_WIDTH columns.
    Falls back to W (the configured display width) if size cannot be queried."""
    try:
        return max(MIN_WIDTH, min(shutil.get_terminal_size().columns - TERM_MARGIN, MAX_WIDTH))
    except Exception:
        return W


def _box_row(content, inner, border_color=CYAN):
    """Return a box content row: ║  <content><padding>  ║
    inner = total inner width (box width minus the two border chars).
    BOX_PADDING spaces are added on each side of the content."""
    pad = max(0, inner - BOX_PADDING - _vis(content))
    return (f"{border_color}{BOLD}║{RST}  {content}"
            f"{' ' * pad}  {border_color}{BOLD}║{RST}")


def _box_top(inner, border_color=CYAN):
    return f"{border_color}{BOLD}╔{'═' * inner}╗{RST}"


def _box_mid(inner, border_color=CYAN):
    return f"{border_color}{BOLD}╠{'═' * inner}╣{RST}"


def _box_bot(inner, border_color=CYAN):
    return f"{border_color}{BOLD}╚{'═' * inner}╝{RST}"

# ── Shared state ───────────────────────────────────────────────────────────────
_force_full = threading.Event()
_running    = True


# ── Helpers ────────────────────────────────────────────────────────────────────
def fetch(url, timeout=HTTP_TIMEOUT):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "protonwg-sentinel/5"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


def fmt_dur(s):
    if s < 60:   return f"{s}s"
    if s < 3600: return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def row(label, value, color=RST, indent=0):
    pad = "    " * indent
    print(f"{pad}  {DIM}▸{RST}  {BOLD}{label:<22}{RST}  {color}{value}{RST}")


def section(title):
    w = _tw()
    fill = max(4, w - _vis(title) - 8)
    print(f"\n  {BOLD}{CYAN}┌─{RST}  {BOLD}{title}{RST}  {DIM}{'─' * fill}{RST}")


def asn_code(field):
    p = (field or "").strip().split()
    return p[0].upper() if p else ""


def is_proton_internal(ip_str):
    """
    Returns True if the IP is a ProtonVPN internal resolver pushed into the
    WireGuard tunnel (e.g. 10.12.5.13). These are safe — not a DNS leak.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PROTON_INTERNAL_RANGES)
    except ValueError:
        return False


def now_str():
    utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    loc = datetime.now().strftime("%H:%M:%S local")
    return utc, loc


# ── Enter-key listener (background thread) ────────────────────────────────────
def _enter_listener():
    """
    Waits for Enter in raw-terminal mode so it doesn't interfere with normal
    output.  Sets _force_full to trigger an immediate full report.
    """
    global _running
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except Exception:
        return   # not a tty (e.g. piped input) — disable silently

    try:
        tty.setraw(fd)
        while _running:
            try:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    _force_full.set()
                elif ch in ("\x03", "\x04"):   # Ctrl-C / Ctrl-D in raw mode
                    _running = False
                    sys.exit(0)
            except Exception:
                break
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass


# ── System info ────────────────────────────────────────────────────────────────
def get_system():
    return {
        "hostname": socket.gethostname(),
        "os":       f"{platform.system()} {platform.release()}",
        "arch":     platform.machine(),
        "python":   platform.python_version(),
    }


# ── WireGuard handshake ────────────────────────────────────────────────────────
def check_wg(iface):
    try:
        out = subprocess.check_output(
            ["sudo", "wg", "show", iface, "latest-handshakes"],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        parts = out.strip().split()
        if len(parts) < 2:
            return {"level": "error", "msg": "No peers on interface"}
        ts = int(parts[1])
    except subprocess.TimeoutExpired:
        return {"level": "error", "msg": "wg timed out"}
    except subprocess.CalledProcessError as e:
        return {"level": "error", "msg": f"wg exit {e.returncode} — interface up?"}
    except Exception as e:
        return {"level": "error", "msg": str(e)}

    if ts == 0:
        return {"level": "never", "msg": "Never connected — no handshake recorded"}

    diff = int(time.time()) - ts
    age  = fmt_dur(diff)
    if diff > STALE_DEAD_SEC:
        return {"level": "dead",  "msg": f"Tunnel appears DOWN — handshake {age} ago"}
    if diff > STALE_WARN_SEC:
        return {"level": "stale", "msg": f"Tunnel STALE — handshake {age} ago"}
    return {"level": "ok", "msg": f"Tunnel alive — handshake {age} ago"}


# ── WireGuard configuration validation ───────────────────────────────────────
def check_wg_config(iface):
    """
    Parse `wg show <iface>` output to validate security configuration.
    Checks: AllowedIPs (full-tunnel 0.0.0.0/0), persistent keepalive,
    listening port.  Returns a dict with ok, warnings, and info lists.
    """
    result = {"ok": True, "warnings": [], "info": []}
    try:
        out = subprocess.check_output(
            ["sudo", "wg", "show", iface],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
    except FileNotFoundError:
        result["warnings"].append("wg not found — install wireguard-tools")
        return result
    except Exception as e:
        result["warnings"].append(f"Cannot read config: {e}")
        return result

    has_full_tunnel = False
    for line in out.splitlines():
        ls = line.strip().lower()
        if ls.startswith("allowed ips:"):
            ips = line.split(":", 1)[1].strip()
            if "0.0.0.0/0" in ips:
                has_full_tunnel = True
                result["info"].append(f"AllowedIPs: {ips} (full-tunnel) ✓")
            else:
                result["warnings"].append(
                    f"AllowedIPs may allow traffic bypass: {ips}")
                result["ok"] = False
        elif ls.startswith("persistent keepalive:"):
            val = line.split(":", 1)[1].strip()
            result["info"].append(f"Persistent keepalive: {val}")
        elif ls.startswith("listening port:"):
            val = line.split(":", 1)[1].strip()
            result["info"].append(f"Listening port: {val}")

    if not has_full_tunnel and result["ok"]:
        result["warnings"].append(
            "AllowedIPs 0.0.0.0/0 not confirmed — split-tunnel or config unreadable")
    return result


# ── Endpoint ping latency ──────────────────────────────────────────────────────
def ping_wg_endpoint(iface):
    """Reads the WireGuard peer endpoint and pings it for round-trip latency."""
    try:
        out = subprocess.check_output(
            ["sudo", "wg", "show", iface, "endpoints"],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        parts = out.strip().split()
        if len(parts) < 2:
            return {"ok": False, "endpoint": "?", "latency_ms": "?",
                    "msg": "No endpoint found"}
        endpoint_raw = parts[1]
        host = (endpoint_raw.split("]")[0].lstrip("[")
                if endpoint_raw.startswith("[")
                else endpoint_raw.rsplit(":", 1)[0])

        ping_out = subprocess.check_output(
            ["ping", "-c", "3", "-W", "2", host],
            text=True, stderr=subprocess.DEVNULL, timeout=12)
        for line in ping_out.splitlines():
            if "rtt" in line or "round-trip" in line:
                nums = line.split("=")[-1].strip().split("/")
                if len(nums) >= 2:
                    return {"ok": True, "endpoint": host,
                            "latency_ms": nums[1], "msg": ""}
        return {"ok": False, "endpoint": host, "latency_ms": "?",
                "msg": "Could not parse RTT"}
    except FileNotFoundError:
        return {"ok": False, "endpoint": "?", "latency_ms": "?",
                "msg": "ping not found — install iputils-ping"}
    except Exception as e:
        return {"ok": False, "endpoint": "?", "latency_ms": "?", "msg": str(e)}


# ── Routing sanity check ───────────────────────────────────────────────────────
def check_routing(iface):
    """
    Confirms the default route (or split-default 0/1 + 128/1) goes through
    the WireGuard interface so traffic isn't leaking outside the tunnel.
    """
    result = {"default_via_vpn": False, "routes": [], "warning": ""}
    try:
        out = subprocess.check_output(
            ["ip", "route", "show"], text=True,
            stderr=subprocess.DEVNULL, timeout=5)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        result["routes"] = lines
        for line in lines:
            if line.startswith("default") and iface in line:
                result["default_via_vpn"] = True
                break
        if not result["default_via_vpn"]:
            half = [l for l in lines
                    if ("0.0.0.0/1" in l or "128.0.0.0/1" in l) and iface in l]
            if len(half) >= 2:
                result["default_via_vpn"] = True
                result["warning"] = "Split-default routing (0/1 + 128/1) — OK"
        if not result["default_via_vpn"]:
            result["warning"] = (
                f"⚠️  Default route does NOT use {iface} "
                "— traffic may bypass VPN!")
    except FileNotFoundError:
        result["warning"] = "ip command not found — install iproute2"
    except Exception as e:
        result["warning"] = f"Route check error: {e}"
    return result


# ── Kill-switch detection ──────────────────────────────────────────────────────
def check_killswitch():
    """
    Looks for DROP rules in iptables OUTPUT chain or nftables ruleset.
    An active kill switch blocks cleartext traffic if the VPN tunnel drops.
    """
    result = {"active": False, "details": ""}
    try:
        out = subprocess.check_output(
            ["iptables", "-L", "OUTPUT", "-n", "--line-numbers"],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        drops = [l for l in out.splitlines() if "DROP" in l]
        if drops:
            result["active"] = True
            result["details"] = f"{len(drops)} DROP rule(s) in iptables OUTPUT ✓"
        else:
            result["details"] = "No DROP rules found — kill switch may be off"
        return result
    except FileNotFoundError:
        pass
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["nft", "list", "ruleset"],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        lower = out.lower()
        if "drop" in lower and any(k in lower for k in ("vpn", "wg", "wireguard")):
            result["active"] = True
            result["details"] = "nftables DROP rules referencing VPN found ✓"
        else:
            result["details"] = "nftables: no VPN-specific DROP rules detected"
        return result
    except FileNotFoundError:
        result["details"] = "iptables/nft unavailable — cannot verify kill switch"
    except Exception as e:
        result["details"] = str(e)
    return result


# ── IP / geolocation ──────────────────────────────────────────────────────────
def get_ipv4():
    d = fetch("https://api.ipify.org?format=json")
    return (d or {}).get("ip")

def get_ipv6():
    d = fetch("https://api6.ipify.org?format=json")
    return (d or {}).get("ip")

def get_ip_api(ip):
    """ip-api.com — country, city, ISP, ASN, timezone, coordinates."""
    fields = ("status,country,countryCode,regionName,city,zip,"
              "lat,lon,timezone,isp,org,as,query")
    return fetch(f"http://ip-api.com/json/{ip}?fields={fields}") or {}

def get_ipinfo(ip):
    """ipinfo.io — org, ASN, hostname, region, timezone."""
    return fetch(f"https://ipinfo.io/{ip}/json") or {}

def get_ipwho(ip):
    """ipwho.is — continent, coordinates, connection ASN."""
    return fetch(f"https://ipwho.is/{ip}") or {}

def check_proton(asn):
    """Classify exit ASN: Proton-owned / known partner / unknown."""
    if not asn:
        return {"level": "error", "msg": "ASN could not be determined"}
    label, trust = ASN_LABELS.get(asn, (asn, "?"))
    if asn in PROTON_OWNED_ASN:
        return {"level": "owned",
                "msg": f"IP block owned directly by Proton AG {trust}  [{label}]"}
    if asn in PROTON_PARTNER_ASN:
        return {"level": "partner",
                "msg": f"Known ProtonVPN DC partner (Proton-controlled) {trust}  [{label}]"}
    return {"level": "unknown",
            "msg": f"NOT recognised as Proton or known partner ({asn})"}


# ── DNS leak checks ────────────────────────────────────────────────────────────
def dns_standard():
    """
    Standard DNS leak check via ipleak.net API.
    Returns which resolvers your system used to reach the internet.
    Source: https://ipleak.net
    """
    d = fetch("https://api.ipleak.net/dnsdetect/", timeout=DNS_TIMEOUT)
    if not d:
        return [{"ip": "?", "isp": "ipleak.net unreachable", "country_code": "?"}]
    items = d if isinstance(d, list) else [d]
    out = [{"ip": e.get("ip","?"),
            "isp": e.get("isp") or e.get("org","?"),
            "country_code": e.get("country_code","?")} for e in items]
    return out or [{"ip": "?", "isp": "no data", "country_code": "?"}]


def dns_advanced():
    """
    Advanced DNS leak check — same method as dnsleaktest.com Extended Test.
    Backend: bash.ws  Source: https://bash.ws

    Steps:
      1. Resolve 6 random subdomains of bash.ws so bash.ws logs which
         resolvers your machine used.
      2. Fetch the resolver list bash.ws collected for our session ID.
      3. If bash.ws is unreachable, fall back to /etc/resolv.conf and
         correctly label ProtonVPN internal resolvers.
    """
    uid = "".join(random.choices(string.digits, k=10))
    for i in range(6):
        try:
            socket.getaddrinfo(f"{uid}-{i}.bash.ws", None,
                               socket.AF_UNSPEC, socket.SOCK_STREAM)
        except Exception:
            pass
        time.sleep(0.15)

    d = fetch(f"https://bash.ws/dnsleak/test/{uid}?json", timeout=DNS_TIMEOUT)
    if d and isinstance(d, list):
        out = [{"ip": e.get("ip","?"), "isp": e.get("isp","?"),
                "country_code": e.get("country_code","?")}
               for e in d if e.get("type") == "dns"]
        if out:
            return out

    # Fallback: read /etc/resolv.conf directly
    resolvers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        resolvers.append({
                            "ip": ip,
                            "isp": ("ProtonVPN internal tunnel resolver"
                                    if is_proton_internal(ip)
                                    else "resolv.conf entry (unverified)"),
                            "country_code": "—",
                        })
    except Exception:
        pass

    return resolvers or [{"ip": "?",
                          "isp": "bash.ws unreachable + resolv.conf unreadable",
                          "country_code": "?"}]


def assess_dns(resolvers, vpn_asn):
    """
    Classify DNS resolvers.

    Rules (in priority order):
      1. All resolvers are RFC1918 / CGNAT addresses  → ProtonVPN internal, SAFE ✓
      2. ISP strings mention Proton keywords           → Proton DNS ✓
      3. Exit ASN is known Proton infrastructure       → traffic exits via Proton ✓
      4. Otherwise                                     → possible leak ⚠
    """
    if not resolvers or resolvers[0]["ip"] == "?":
        return "warn", "Could not reach leak-test endpoint"

    if all(is_proton_internal(r.get("ip","")) for r in resolvers):
        return ("ok",
                f"{len(resolvers)} resolver(s) are ProtonVPN internal tunnel "
                f"DNS (RFC1918) ✓ — no leak")

    combined = " ".join(
        f"{r.get('isp','')} {r.get('country_code','')}" for r in resolvers
    ).lower()

    if any(kw in combined for kw in PROTON_DNS_KW):
        return "ok", f"{len(resolvers)} resolver(s) confirmed as ProtonVPN DNS ✓"
    if vpn_asn in PROTON_OWNED_ASN | PROTON_PARTNER_ASN:
        return "ok", f"{len(resolvers)} resolver(s) — exiting via Proton network ✓"

    return ("leak",
            f"⚠️  {len(resolvers)} resolver(s) may NOT be ProtonVPN — possible DNS leak!")


def dns_all_safe(std, adv, vpn_asn):
    return (assess_dns(std, vpn_asn)[0] in ("ok", "warn") and
            assess_dns(adv, vpn_asn)[0] in ("ok", "warn"))


# ══════════════════════════════════════════════════════════════════════════════
#  RENDER — Full detailed report
# ══════════════════════════════════════════════════════════════════════════════
def render_full(sys_info, wg, wg_config, ping_r, routing, ks,
                ipv4, ipv6, ip_api_d, ipinf_d, ipwho_d,
                proton, vpn_asn, std, adv):

    print("\033[2J\033[H", end="")
    utc, loc = now_str()
    w     = _tw()
    inner = w - 4

    # ── Header box ─────────────────────────────────────────────────────────────
    t1 = f"{BOLD}✦  protonwg-sentinel{RST}  {DIM}v5.0{RST}"
    t2 = f"{DIM}{utc}  ·  {loc}{RST}"
    t3 = f"{DIM}Press {BOLD}Enter{RST}{DIM} for a fresh full report   ·   Ctrl-C to quit{RST}"
    print(f"\n{_box_top(inner)}")
    print(_box_row(t1, inner))
    print(_box_row(t2, inner))
    print(_box_mid(inner))
    print(_box_row(t3, inner))
    print(f"{_box_bot(inner)}")

    # ── System ─────────────────────────────────────────────────────────────────
    section("🖥   SYSTEM")
    row("Hostname", sys_info["hostname"])
    row("OS",       sys_info["os"])
    row("Arch",     sys_info["arch"])
    row("Python",   sys_info["python"])

    # ── WireGuard ──────────────────────────────────────────────────────────────
    section(f"🔒  WIREGUARD  [{INTERFACE}]")
    lvl  = wg["level"]
    wg_c = GREEN if lvl == "ok" else (YELLOW if lvl == "stale" else RED)
    wg_i = "✅" if lvl == "ok" else ("⚠️ " if lvl == "stale" else "❌")
    print(f"  {wg_i}  {wg_c}{wg['msg']}{RST}")

    if ping_r["ok"]:
        try:
            ms    = float(ping_r["latency_ms"])
            lat_c = GREEN if ms < 50 else YELLOW if ms < 120 else RED
        except ValueError:
            lat_c = DIM
        print(f"  📡  {BOLD}Endpoint:{RST} {DIM}{ping_r['endpoint']}{RST}  "
              f"latency {lat_c}{ping_r['latency_ms']} ms avg{RST}")
    else:
        print(f"  📡  {BOLD}Endpoint ping:{RST} {DIM}{ping_r['msg']}{RST}")

    # ── WireGuard config validation
    section("⚙️   WIREGUARD CONFIG VALIDATION")
    if wg_config["info"]:
        for line in wg_config["info"]:
            print(f"  ✅  {GREEN}{line}{RST}")
    if wg_config["warnings"]:
        for line in wg_config["warnings"]:
            c = YELLOW if "split-tunnel" in line.lower() or "unreadable" in line.lower() else RED
            print(f"  ⚠️   {c}{line}{RST}")
    if not wg_config["info"] and not wg_config["warnings"]:
        print(f"  {DIM}No configuration data retrieved{RST}")

    # ── Routing & kill switch ──────────────────────────────────────────────────
    section("🛤   ROUTING & KILL SWITCH")

    if routing["default_via_vpn"]:
        note = f"  {DIM}{routing['warning']}{RST}" if routing["warning"] else ""
        print(f"  ✅  {GREEN}Default route confirmed via {INTERFACE}{RST}{note}")
    else:
        print(f"  ❌  {RED}{routing['warning'] or 'Default route not through VPN'}{RST}")

    if ks["active"]:
        print(f"  ✅  {GREEN}Kill switch active — {ks['details']}{RST}")
    else:
        ks_c = YELLOW if "unavailable" in ks["details"].lower() else ORANGE
        print(f"  ⚠️   {ks_c}Kill switch: {ks['details']}{RST}")

    # ── IP & Location ──────────────────────────────────────────────────────────
    section("🌐  IP ADDRESS & LOCATION")

    pc = (GREEN if proton["level"] == "owned"
          else ORANGE if proton["level"] == "partner" else RED)
    pi = ("✅" if proton["level"] == "owned"
          else "🟠" if proton["level"] == "partner" else "❌")

    row("IPv4 (exit IP)", ipv4 or "not detected", CYAN if ipv4 else RED)
    row("IPv6 (exit IP)", ipv6 or "not detected", CYAN if ipv6 else DIM)
    print(f"\n  {pi}  {BOLD}ProtonVPN:{RST} {pc}{proton['msg']}{RST}")

    # Source 1 — ip-api.com
    print(f"\n  {BOLD}Source 1  {DIM}ip-api.com{RST}")
    if ip_api_d:
        row("Country",       f"{ip_api_d.get('country','?')} ({ip_api_d.get('countryCode','?')})", indent=1)
        row("Region / City", f"{ip_api_d.get('regionName','?')} / {ip_api_d.get('city','?')}", indent=1)
        row("ZIP",           ip_api_d.get("zip","?"), indent=1)
        row("Coords",        f"lat {ip_api_d.get('lat','?')},  lon {ip_api_d.get('lon','?')}", indent=1)
        row("Timezone",      ip_api_d.get("timezone","?"), indent=1)
        row("ISP",           ip_api_d.get("isp","?"), indent=1)
        row("Org",           ip_api_d.get("org","?"), indent=1)
        row("ASN",           ip_api_d.get("as","?"), indent=1)
    else:
        print(f"      {RED}unavailable{RST}")

    # Source 2 — ipinfo.io
    print(f"\n  {BOLD}Source 2  {DIM}ipinfo.io{RST}")
    if ipinf_d:
        row("IP",            ipinf_d.get("ip","?"), indent=1)
        row("City / Region", f"{ipinf_d.get('city','?')} / {ipinf_d.get('region','?')}", indent=1)
        row("Country",       ipinf_d.get("country","?"), indent=1)
        row("Org / ASN",     ipinf_d.get("org","?"), indent=1)
        row("Hostname",      ipinf_d.get("hostname","none"), indent=1)
        row("Timezone",      ipinf_d.get("timezone","?"), indent=1)
    else:
        print(f"      {RED}unavailable{RST}")

    # Source 3 — ipwho.is
    print(f"\n  {BOLD}Source 3  {DIM}ipwho.is{RST}")
    if ipwho_d and ipwho_d.get("success"):
        conn = ipwho_d.get("connection", {})
        row("IP",            ipwho_d.get("ip","?"), indent=1)
        row("Country",       f"{ipwho_d.get('country','?')} ({ipwho_d.get('country_code','?')})", indent=1)
        row("Region / City", f"{ipwho_d.get('region','?')} / {ipwho_d.get('city','?')}", indent=1)
        row("Continent",     ipwho_d.get("continent","?"), indent=1)
        row("Coords",        f"lat {ipwho_d.get('latitude','?')},  lon {ipwho_d.get('longitude','?')}", indent=1)
        row("ISP",           conn.get("isp","?"), indent=1)
        row("Org",           conn.get("org","?"), indent=1)
        row("ASN",           str(conn.get("asn","?")), indent=1)
    else:
        print(f"      {RED}unavailable{RST}")

    # ── DNS leak ───────────────────────────────────────────────────────────────
    section("🔍  DNS LEAK TEST")

    def show_dns(label, resolvers):
        level, summary = assess_dns(resolvers, vpn_asn)
        ic = "✅" if level == "ok" else ("⚠️ " if level == "warn" else "❌")
        co = GREEN if level == "ok" else (YELLOW if level == "warn" else RED)
        print(f"\n  {BOLD}{label}{RST}")
        print(f"  {ic}  {co}{summary}{RST}")
        for r in resolvers:
            ip  = r.get("ip","?")
            isp = r.get("isp") or "?"
            cc  = r.get("country_code","?")
            if is_proton_internal(ip):
                tag = f"  {GREEN}← ProtonVPN internal tunnel DNS ✓{RST}"
            elif ip in KNOWN_SAFE_DNS_IPS:
                tag = f"  {GREEN}← known-safe public DNS ✓{RST}"
            elif vpn_asn in PROTON_OWNED_ASN | PROTON_PARTNER_ASN:
                tag = f"  {GREEN}← Proton network ✓{RST}"
            elif any(kw in isp.lower() for kw in PROTON_DNS_KW):
                tag = f"  {GREEN}← Proton DNS ✓{RST}"
            else:
                tag = f"  {RED}← possible leak — not Proton DNS{RST}"
            print(f"      {DIM}→{RST}  {CYAN}{ip:<42}{RST}  {isp} [{cc}]{tag}")

    show_dns("Standard check  —  ipleak.net API", std)
    show_dns("Advanced check  —  bash.ws  (same backend as dnsleaktest.com Extended Test)", adv)
    print(f"\n  {DIM}Manual check: https://www.dnsleaktest.com → Extended Test{RST}")

    # ── Footer ─────────────────────────────────────────────────────────────────
    print(f"\n{DIM}{'─' * w}{RST}")
    print(f"  {DIM}Switching to compact status in {BOLD}3s{RST}{DIM}…   "
          f"Press {BOLD}Enter{RST}{DIM} to repeat this report{RST}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  RENDER — Compact live status (shown between full reports)
# ══════════════════════════════════════════════════════════════════════════════
def render_compact(wg, ping_r, routing, ks, ipv4, ipv6,
                   proton, vpn_asn, std, adv, last_full_utc, next_full_in,
                   location=""):
    """
    Single-screen status dashboard.
    Full-width boxed banner at the top — green, yellow, or red.
    Individual indicator lines below for every check.
    """
    print("\033[2J\033[H", end="")
    utc, loc = now_str()
    w     = _tw()
    inner = w - 4

    lvl       = wg["level"]
    route_ok  = routing["default_via_vpn"]
    std_lvl   = assess_dns(std, vpn_asn)[0]
    adv_lvl   = assess_dns(adv, vpn_asn)[0]
    dns_leak  = (std_lvl == "leak" or adv_lvl == "leak")
    proton_ok = proton["level"] in ("owned", "partner")

    all_green = (lvl == "ok" and route_ok and not dns_leak and proton_ok)
    any_red   = (lvl in ("dead", "never", "error") or not route_ok or dns_leak)

    if all_green:
        bdr_c      = GREEN
        banner_txt = f"{BOLD}  ✅  CONNECTED  —  ProtonVPN WireGuard tunnel is healthy  ✓{RST}"
    elif any_red:
        bdr_c      = RED
        banner_txt = f"{BOLD}  ❌  WARNING  —  VPN issue detected — check details below{RST}"
    else:
        bdr_c      = YELLOW
        banner_txt = f"{BOLD}  ⚠️   DEGRADED  —  some checks need attention{RST}"

    # Status banner box
    print(f"\n{_box_top(inner, bdr_c)}")
    print(_box_row(banner_txt, inner, bdr_c))
    print(f"{_box_bot(inner, bdr_c)}")

    # Timestamps & hints
    print(f"\n  {DIM}🕐  {utc}  ·  {loc}{RST}")
    print(f"  {DIM}📋  Last full report: {BOLD}{last_full_utc}{RST}"
          f"{DIM}   ·   Next auto-check in: {BOLD}{next_full_in}s{RST}")
    print(f"  {DIM}⌨   Press {BOLD}Enter{RST}{DIM} for full report   ·   Ctrl-C to quit{RST}")

    print(f"\n  {DIM}{'─' * (w - 4)}{RST}")

    # WireGuard
    wg_c  = GREEN if lvl == "ok" else (YELLOW if lvl == "stale" else RED)
    wg_ic = "✅" if lvl == "ok" else ("⚠️ " if lvl == "stale" else "❌")
    print(f"  {wg_ic}  {BOLD}{CYAN}{'WireGuard':<20}{RST}  {wg_c}{wg['msg']}{RST}")

    # Latency
    if ping_r["ok"]:
        try:
            ms    = float(ping_r["latency_ms"])
            lat_c = GREEN if ms < 50 else YELLOW if ms < 120 else RED
        except ValueError:
            lat_c = DIM
        print(f"  📡  {BOLD}{CYAN}{'Endpoint latency':<20}{RST}  "
              f"{lat_c}{ping_r['latency_ms']} ms{RST}  "
              f"{DIM}→ {ping_r['endpoint']}{RST}")
    else:
        print(f"  📡  {BOLD}{CYAN}{'Endpoint latency':<20}{RST}  {DIM}{ping_r['msg']}{RST}")

    # Exit IP
    ip_c = CYAN if ipv4 else RED
    print(f"  🌐  {BOLD}{CYAN}{'Exit IPv4':<20}{RST}  {ip_c}{ipv4 or 'not detected'}{RST}")
    if ipv6:
        print(f"  🌐  {BOLD}{CYAN}{'Exit IPv6':<20}{RST}  {CYAN}{ipv6}{RST}")

    # ProtonVPN ASN
    pc = (GREEN if proton["level"] == "owned"
          else ORANGE if proton["level"] == "partner" else RED)
    pi = ("✅" if proton["level"] == "owned"
          else "🟠" if proton["level"] == "partner" else "❌")
    print(f"  {pi}  {BOLD}{CYAN}{'ProtonVPN ASN':<20}{RST}  {pc}{proton['msg']}{RST}")

    # Exit location
    if location:
        print(f"  📍  {BOLD}{CYAN}{'Location':<20}{RST}  {CYAN}{location}{RST}")

    # Default route
    r_ic  = "✅" if route_ok else "❌"
    r_c   = GREEN if route_ok else RED
    r_msg = (f"Default route via {INTERFACE} ✓" if route_ok
             else (routing["warning"] or f"Not routed via {INTERFACE}"))
    print(f"  {r_ic}  {BOLD}{CYAN}{'Default route':<20}{RST}  {r_c}{r_msg}{RST}")

    # Kill switch
    ks_ic = "✅" if ks["active"] else "⚠️ "
    ks_c  = GREEN if ks["active"] else YELLOW
    print(f"  {ks_ic}  {BOLD}{CYAN}{'Kill switch':<20}{RST}  {ks_c}{ks['details']}{RST}")

    # DNS checks
    for label, lvl2, msg in (
        ("DNS standard", std_lvl, assess_dns(std, vpn_asn)[1]),
        ("DNS advanced", adv_lvl, assess_dns(adv, vpn_asn)[1]),
    ):
        d_ic = "✅" if lvl2 == "ok" else ("⚠️ " if lvl2 == "warn" else "❌")
        d_c  = GREEN if lvl2 == "ok" else (YELLOW if lvl2 == "warn" else RED)
        print(f"  {d_ic}  {BOLD}{CYAN}{label:<20}{RST}  {d_c}{msg}{RST}")

    print(f"  {DIM}{'─' * (w - 4)}{RST}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Data collection helper
# ══════════════════════════════════════════════════════════════════════════════
def collect_all():
    """Gather all network data. Called on startup and on every full re-check."""
    ipv4     = get_ipv4()
    ipv6     = get_ipv6()
    ip_api_d = get_ip_api(ipv4) if ipv4 else {}
    ipinf_d  = get_ipinfo(ipv4) if ipv4 else {}
    ipwho_d  = get_ipwho(ipv4)  if ipv4 else {}
    vpn_asn  = asn_code(ip_api_d.get("as",""))
    proton   = check_proton(vpn_asn)
    std      = dns_standard()
    adv      = dns_advanced()
    city     = (ip_api_d or {}).get("city", "")
    cc       = (ip_api_d or {}).get("countryCode", "")
    location = f"{city}, {cc}" if city and cc else ""
    return dict(ipv4=ipv4, ipv6=ipv6, ip_api_d=ip_api_d, ipinf_d=ipinf_d,
                ipwho_d=ipwho_d, vpn_asn=vpn_asn, proton=proton,
                std=std, adv=adv, location=location)


# ══════════════════════════════════════════════════════════════════════════════
#  Historical connection logging
# ══════════════════════════════════════════════════════════════════════════════
def log_connection(data, wg, proton, vpn_asn, std_status, adv_status):
    """
    Append a structured connection record to the JSON log file.
    Keeps the last 1 000 records.  Silently skips if the file is unwritable.
    Log location: ~/.local/share/protonwg-sentinel/connections.json
    """
    record = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "asn":          vpn_asn,
        "provider":     ASN_LABELS.get(vpn_asn, (vpn_asn,))[0],
        "proton_level": proton["level"],
        "ip":           data.get("ipv4"),
        "ipv6":         data.get("ipv6"),
        "location":     data.get("location", ""),
        "wg_status":    wg["level"],
        "dns_standard": std_status,
        "dns_advanced": adv_status,
    }
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        records = []
        if os.path.isfile(LOG_FILE):
            with open(LOG_FILE, encoding="utf-8") as f:
                records = json.load(f)
        records.append(record)
        if len(records) > 1000:
            records = records[-1000:]
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════
def main():
    global _running

    signal.signal(signal.SIGINT,
                  lambda s, f: (print(f"\n{DIM}protonwg-sentinel stopped.{RST}\n"),
                                sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    sys_info = get_system()

    # Start Enter-key listener thread
    listener = threading.Thread(target=_enter_listener, daemon=True)
    listener.start()

    # ── Boot splash ────────────────────────────────────────────────────────────
    print("\033[2J\033[H", end="")
    w     = _tw()
    inner = w - 4
    t1 = f"{BOLD}✦  protonwg-sentinel{RST}  {DIM}v5.0{RST}"
    print(f"\n{_box_top(inner)}")
    print(_box_row(t1, inner))
    print(f"{_box_bot(inner)}\n")
    print(f"  {DIM}⏳  Gathering data — fetching IPs, running DNS leak tests,{RST}")
    print(f"  {DIM}    pinging WireGuard endpoint…  (this takes ~10s){RST}\n")

    # ── Initial full data collection ───────────────────────────────────────────
    data          = collect_all()
    wg            = check_wg(INTERFACE)
    wg_config     = check_wg_config(INTERFACE)
    ping_r        = ping_wg_endpoint(INTERFACE)
    routing       = check_routing(INTERFACE)
    ks            = check_killswitch()
    last_full_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    last_full_ts  = time.time()
    log_connection(data, wg, data["proton"], data["vpn_asn"],
                   assess_dns(data["std"], data["vpn_asn"])[0],
                   assess_dns(data["adv"], data["vpn_asn"])[0])

    # ── Show first full report ─────────────────────────────────────────────────
    render_full(sys_info, wg, wg_config, ping_r, routing, ks,
                data["ipv4"], data["ipv6"],
                data["ip_api_d"], data["ipinf_d"], data["ipwho_d"],
                data["proton"], data["vpn_asn"],
                data["std"], data["adv"])

    time.sleep(3)   # pause so user can read the full report

    # ── Main loop ──────────────────────────────────────────────────────────────
    while True:
        # Fast local checks run every iteration (no network needed)
        wg      = check_wg(INTERFACE)
        ping_r  = ping_wg_endpoint(INTERFACE)
        routing = check_routing(INTERFACE)
        ks      = check_killswitch()

        elapsed      = int(time.time() - last_full_ts)
        next_full_in = max(0, FULL_INTERVAL - elapsed)
        force        = _force_full.is_set()

        if force or elapsed >= FULL_INTERVAL:
            # ── Full re-check ──────────────────────────────────────────────────
            _force_full.clear()
            print("\033[2J\033[H", end="")
            print(f"\n  {BOLD}{CYAN}↻{RST}  {DIM}Re-fetching all network data…{RST}\n")
            data          = collect_all()
            wg            = check_wg(INTERFACE)
            wg_config     = check_wg_config(INTERFACE)
            ping_r        = ping_wg_endpoint(INTERFACE)
            routing       = check_routing(INTERFACE)
            ks            = check_killswitch()
            last_full_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            last_full_ts  = time.time()
            log_connection(data, wg, data["proton"], data["vpn_asn"],
                           assess_dns(data["std"], data["vpn_asn"])[0],
                           assess_dns(data["adv"], data["vpn_asn"])[0])

            render_full(sys_info, wg, wg_config, ping_r, routing, ks,
                        data["ipv4"], data["ipv6"],
                        data["ip_api_d"], data["ipinf_d"], data["ipwho_d"],
                        data["proton"], data["vpn_asn"],
                        data["std"], data["adv"])
            time.sleep(3)
            continue

        # ── Compact status ─────────────────────────────────────────────────────
        render_compact(wg, ping_r, routing, ks,
                       data["ipv4"], data["ipv6"],
                       data["proton"], data["vpn_asn"],
                       data["std"], data["adv"],
                       last_full_utc, next_full_in,
                       data.get("location", ""))

        time.sleep(COMPACT_INTERVAL)


if __name__ == "__main__":
    main()
