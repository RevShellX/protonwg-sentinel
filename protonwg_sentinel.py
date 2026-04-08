#!/usr/bin/env python3
"""
protonwg-sentinel  v5.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WireGuard + ProtonVPN connection monitor — stdlib only, no pip needed

Behaviour:
  • On startup  : full detailed report (all checks, all sources)
  • After that  : compact live status — green = connected, red = down
  • Press ENTER : force immediate full re-check and detailed report
  • Ctrl-C      : quit

Checks:
  • WireGuard tunnel handshake freshness
  • Public IPv4 and IPv6 exit addresses
  • Full location + ISP info  (3 independent sources)
  • ProtonVPN ASN ownership   (green / orange / red)
  • DNS leak — standard (ipleak.net) + advanced (bash.ws / dnsleaktest engine)
  • ProtonVPN internal resolver recognition  (10.x.x.x = safe, not a leak)
  • Default route sanity  (traffic actually goes through VPN interface)
  • Kill-switch detection  (iptables / nftables DROP rules)
  • WireGuard endpoint ping latency
  • System identity: hostname, OS, kernel, architecture

ASN / infrastructure sources:
  • ProtonVPN server map  : https://www.netify.ai/resources/vpns/proton-vpn
  • ASN verified          : https://bgp.he.net  +  https://ipinfo.io
  • Proton-owned ASNs     : https://ipinfo.io/AS209103 | https://ipinfo.io/AS51396

GitHub: https://github.com/YOUR_USERNAME/protonwg-sentinel
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import ipaddress, json, platform, random, signal, socket
import string, subprocess, sys, termios, threading, time, tty
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
W                = 72         # display width
# ──────────────────────────────────────────────────────────────────────────────

# ── ProtonVPN ASN database ─────────────────────────────────────────────────────

# ✅ GREEN — IP blocks owned directly by Proton AG
# Source: https://ipinfo.io/AS209103  |  https://ipinfo.io/AS51396
PROTON_OWNED_ASN = {
    "AS209103",   # Proton AG  (primary)
    "AS51396",    # Proton AG  (secondary)
}

# 🟠 ORANGE — confirmed datacenter partners (leased, Proton-controlled)
# Source: https://www.netify.ai/resources/vpns/proton-vpn  +  bgp.he.net
# NOTE: orange does NOT mean unsafe — traffic is WireGuard-encrypted end-to-end
PROTON_PARTNER_ASN = {
    "AS9009",    # M247 Europe SRL        — most common ProtonVPN exit (EU + US)
    "AS60068",   # Datacamp Limited       — all regions
    "AS212238",  # Datacamp Limited       — secondary ASN
    "AS46562",   # Performive LLC         — Canada / US
    "AS63023",   # GTHost                 — US (Phoenix)
    "AS49981",   # Worldstream B.V.       — Netherlands (Amsterdam)
    "AS24875",   # NovoServe B.V.         — Netherlands (Amsterdam)
    "AS262287",  # Latitude.sh LTDA       — South America / formerly Maxihost
    "AS396356",  # Latitude.sh LLC        — South America / US
}

PROTON_DNS_KW = {"proton", "protonvpn", "proton.me", "proton.ch"}

# ProtonVPN pushes private-range resolvers into the WireGuard tunnel.
# e.g. 10.12.5.13 / 10.12.5.14 — Proton internal DNS, NOT a leak.
PROTON_INTERNAL_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]

# ── ANSI ───────────────────────────────────────────────────────────────────────
RST    = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BG_GRN = "\033[42m"
BG_RED = "\033[41m"
BG_YLW = "\033[43m"
BLACK  = "\033[30m"

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
    print(f"{pad}  {BOLD}{label:<22}{RST} {color}{value}{RST}")


def section(title):
    print(f"\n{DIM}{'─' * W}{RST}")
    print(f"  {BOLD}{CYAN}{title}{RST}")
    print(f"{DIM}{'─' * W}{RST}")


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
    if asn in PROTON_OWNED_ASN:
        return {"level": "owned",
                "msg": "IP block owned directly by Proton AG ✓"}
    if asn in PROTON_PARTNER_ASN:
        return {"level": "partner",
                "msg": "Known ProtonVPN DC partner (leased, Proton-controlled) ✓"}
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
def render_full(sys_info, wg, ping_r, routing, ks,
                ipv4, ipv6, ip_api_d, ipinf_d, ipwho_d,
                proton, vpn_asn, std, adv):

    print("\033[2J\033[H", end="")
    utc, loc = now_str()

    print(f"\n{BOLD}{GREEN}{'═' * W}{RST}")
    print(f"  {BOLD}protonwg-sentinel  v5.0{RST}   {DIM}{utc}  /  {loc}{RST}")
    print(f"{BOLD}{GREEN}{'═' * W}{RST}")
    print(f"  {DIM}Press {BOLD}Enter{RST}{DIM} for a fresh full report  |  Ctrl-C to quit{RST}")

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
            elif vpn_asn in PROTON_OWNED_ASN | PROTON_PARTNER_ASN:
                tag = f"  {GREEN}← Proton network{RST}"
            elif any(kw in isp.lower() for kw in PROTON_DNS_KW):
                tag = f"  {GREEN}← Proton DNS{RST}"
            else:
                tag = f"  {RED}← possible leak — not Proton DNS{RST}"
            print(f"      {DIM}→{RST}  {CYAN}{ip:<42}{RST}  {isp} [{cc}]{tag}")

    show_dns("Standard check  —  ipleak.net API", std)
    show_dns("Advanced check  —  bash.ws  (same backend as dnsleaktest.com Extended Test)", adv)
    print(f"\n  {DIM}Manual check: https://www.dnsleaktest.com → Extended Test{RST}")

    # ── Footer ─────────────────────────────────────────────────────────────────
    print(f"\n{DIM}{'─' * W}")
    print(f"  Switching to compact status in 3s…  |  "
          f"Press Enter to repeat this report{RST}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  RENDER — Compact live status (shown between full reports)
# ══════════════════════════════════════════════════════════════════════════════
def render_compact(wg, ping_r, routing, ks, ipv4, ipv6,
                   proton, vpn_asn, std, adv, last_full_utc, next_full_in):
    """
    Single-screen status dashboard.
    Large coloured banner at the top — green, yellow, or red.
    Individual indicator lines below for every check.
    """
    print("\033[2J\033[H", end="")
    utc, loc = now_str()

    lvl       = wg["level"]
    route_ok  = routing["default_via_vpn"]
    std_lvl   = assess_dns(std, vpn_asn)[0]
    adv_lvl   = assess_dns(adv, vpn_asn)[0]
    dns_leak  = (std_lvl == "leak" or adv_lvl == "leak")
    proton_ok = proton["level"] in ("owned", "partner")

    all_green = (lvl == "ok" and route_ok and not dns_leak and proton_ok)
    any_red   = (lvl in ("dead", "never", "error") or not route_ok or dns_leak)

    if all_green:
        bg, fg      = BG_GRN, BLACK
        banner_txt  = " ✅  CONNECTED — ProtonVPN tunnel healthy "
    elif any_red:
        bg, fg      = BG_RED, BLACK
        banner_txt  = " ❌  WARNING — VPN issue detected "
    else:
        bg, fg      = BG_YLW, BLACK
        banner_txt  = " ⚠️   DEGRADED — some checks need attention "

    pad = max(0, (W - len(banner_txt)) // 2)
    print(f"\n{' ' * pad}{BOLD}{bg}{fg}{banner_txt}{RST}\n")

    print(f"  {DIM}{utc}  /  {loc}{RST}")
    print(f"  {DIM}Last full report : {last_full_utc}{RST}")
    print(f"  {DIM}Next auto-report : {next_full_in}s   "
          f"│  Press {BOLD}Enter{RST}{DIM} for full report now  │  Ctrl-C to quit{RST}")
    print(f"\n{DIM}{'─' * W}{RST}")

    # WireGuard
    wg_c  = GREEN if lvl == "ok" else (YELLOW if lvl == "stale" else RED)
    wg_ic = "✅" if lvl == "ok" else ("⚠️ " if lvl == "stale" else "❌")
    print(f"  {wg_ic}  {BOLD}{'WireGuard':<20}{RST}  {wg_c}{wg['msg']}{RST}")

    # Latency
    if ping_r["ok"]:
        try:
            ms    = float(ping_r["latency_ms"])
            lat_c = GREEN if ms < 50 else YELLOW if ms < 120 else RED
        except ValueError:
            lat_c = DIM
        print(f"  📡  {BOLD}{'Endpoint latency':<20}{RST}  "
              f"{lat_c}{ping_r['latency_ms']} ms{RST}  "
              f"{DIM}→ {ping_r['endpoint']}{RST}")
    else:
        print(f"  📡  {BOLD}{'Endpoint latency':<20}{RST}  {DIM}{ping_r['msg']}{RST}")

    # Exit IP
    ip_c = CYAN if ipv4 else RED
    print(f"  🌐  {BOLD}{'Exit IPv4':<20}{RST}  {ip_c}{ipv4 or 'not detected'}{RST}")
    if ipv6:
        print(f"  🌐  {BOLD}{'Exit IPv6':<20}{RST}  {CYAN}{ipv6}{RST}")

    # ProtonVPN ASN
    pc = (GREEN if proton["level"] == "owned"
          else ORANGE if proton["level"] == "partner" else RED)
    pi = ("✅" if proton["level"] == "owned"
          else "🟠" if proton["level"] == "partner" else "❌")
    print(f"  {pi}  {BOLD}{'ProtonVPN ASN':<20}{RST}  {pc}{proton['msg']}{RST}")

    # Default route
    r_ic  = "✅" if route_ok else "❌"
    r_c   = GREEN if route_ok else RED
    r_msg = (f"Default route via {INTERFACE} ✓" if route_ok
             else (routing["warning"] or f"Not routed via {INTERFACE}"))
    print(f"  {r_ic}  {BOLD}{'Default route':<20}{RST}  {r_c}{r_msg}{RST}")

    # Kill switch
    ks_ic = "✅" if ks["active"] else "⚠️ "
    ks_c  = GREEN if ks["active"] else YELLOW
    print(f"  {ks_ic}  {BOLD}{'Kill switch':<20}{RST}  {ks_c}{ks['details']}{RST}")

    # DNS checks
    for label, lvl2, msg in (
        ("DNS standard", std_lvl, assess_dns(std, vpn_asn)[1]),
        ("DNS advanced", adv_lvl, assess_dns(adv, vpn_asn)[1]),
    ):
        d_ic = "✅" if lvl2 == "ok" else ("⚠️ " if lvl2 == "warn" else "❌")
        d_c  = GREEN if lvl2 == "ok" else (YELLOW if lvl2 == "warn" else RED)
        print(f"  {d_ic}  {BOLD}{label:<20}{RST}  {d_c}{msg}{RST}")

    print(f"{DIM}{'─' * W}{RST}\n")


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
    return dict(ipv4=ipv4, ipv6=ipv6, ip_api_d=ip_api_d, ipinf_d=ipinf_d,
                ipwho_d=ipwho_d, vpn_asn=vpn_asn, proton=proton,
                std=std, adv=adv)


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
    print(f"\n{BOLD}{GREEN}{'═' * W}{RST}")
    print(f"  {BOLD}protonwg-sentinel  v5.0{RST}")
    print(f"{BOLD}{GREEN}{'═' * W}{RST}\n")
    print(f"  {DIM}Gathering data — fetching IPs, running DNS leak tests,{RST}")
    print(f"  {DIM}pinging WireGuard endpoint…  (this takes ~10s){RST}\n")

    # ── Initial full data collection ───────────────────────────────────────────
    data          = collect_all()
    wg            = check_wg(INTERFACE)
    ping_r        = ping_wg_endpoint(INTERFACE)
    routing       = check_routing(INTERFACE)
    ks            = check_killswitch()
    last_full_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    last_full_ts  = time.time()

    # ── Show first full report ─────────────────────────────────────────────────
    render_full(sys_info, wg, ping_r, routing, ks,
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
            print(f"\n  {DIM}Re-fetching all network data…{RST}\n")
            data          = collect_all()
            wg            = check_wg(INTERFACE)
            ping_r        = ping_wg_endpoint(INTERFACE)
            routing       = check_routing(INTERFACE)
            ks            = check_killswitch()
            last_full_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            last_full_ts  = time.time()

            render_full(sys_info, wg, ping_r, routing, ks,
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
                       last_full_utc, next_full_in)

        time.sleep(COMPACT_INTERVAL)


if __name__ == "__main__":
    main()
