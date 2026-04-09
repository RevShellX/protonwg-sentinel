#!/usr/bin/env python3
"""
protonwg-sentinel  v8.0
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
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────
VERSION          = "8.0"
INTERFACE        = "wg0"      # WireGuard interface — auto-detected at startup via detect_wg_interface()
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
    "AS204779",   # Proton AG  (Swiss block — visible on bgp.tools)
    "AS211984",   # Proton AG  (additional EU allocation)
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
    # 31173 Services — Sweden
    "AS39351",   # 31173 Services AB      — Sweden (confirmed ProtonVPN exit)
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
    # Zenlayer — Asia Pacific
    "AS21859",   # Zenlayer Inc.          — APAC / US (ProtonVPN Asia nodes)
    # ColoCrossing — US
    "AS36352",   # ColoCrossing LLC       — US (ProtonVPN US exit nodes)
    # Hostinger — EU
    "AS47583",   # Hostinger International — EU nodes
    # IKOULA — France
    "AS25003",   # IKOULA SAS             — France
    # Serverius — Netherlands
    "AS50673",   # Serverius              — Netherlands (AMS)
    # Psychz Networks — US/APAC
    "AS40676",   # Psychz Networks        — US / APAC
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
    "AS204779": ("Proton AG",        "✓"),
    "AS211984": ("Proton AG",        "✓"),
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
    "AS39351":  ("31173 Services",   "⚙"),
    "AS202053": ("Creanova",         "⚙"),
    "AS20473":  ("Choopa/Vultr",     "⚙"),
    "AS13335":  ("Cloudflare",       "⚙"),
    "AS8452":   ("Telecom Egypt",    "⚙"),
    "AS16247":  ("Akamai/Linode",    "⚙"),
    "AS21859":  ("Zenlayer",         "⚙"),
    "AS36352":  ("ColoCrossing",     "⚙"),
    "AS47583":  ("Hostinger",        "⚙"),
    "AS25003":  ("IKOULA",           "⚙"),
    "AS50673":  ("Serverius",        "⚙"),
    "AS40676":  ("Psychz Networks",  "⚙"),
}

# Well-known privacy-respecting public DNS resolvers (safe when inside Proton tunnel)
KNOWN_SAFE_DNS_IPS = {
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS  (AS13335 — Proton partner)
    "9.9.9.9", "149.112.112.112",    # Quad9  (privacy-focused)
}

# ── ANSI ───────────────────────────────────────────────────────────────────────
RST      = "\033[0m"
BOLD     = "\033[1m"
DIM      = "\033[2m"
ITALIC   = "\033[3m"
# Standard bright colours
RED      = "\033[91m"
YELLOW   = "\033[93m"
GREEN    = "\033[92m"
CYAN     = "\033[96m"
BLUE     = "\033[94m"
MAGENTA  = "\033[95m"
WHITE    = "\033[97m"
BLACK    = "\033[30m"
# 256-colour extended palette — for depth and gradient-like transitions
ORANGE   = "\033[38;5;208m"
AMBER    = "\033[38;5;214m"   # warm amber — between yellow and orange
GOLD     = "\033[38;5;220m"   # gold accent
LIME     = "\033[38;5;154m"   # bright lime green
MINT     = "\033[38;5;121m"   # soft mint
TEAL     = "\033[38;5;43m"    # deep teal
AQUA     = "\033[38;5;87m"    # bright aqua
INDIGO   = "\033[38;5;105m"   # indigo / deep blue-purple
PURPLE   = "\033[38;5;141m"   # medium purple
LAVENDER = "\033[38;5;183m"   # light lavender
ROSE     = "\033[38;5;204m"   # rose / soft red
CORAL    = "\033[38;5;209m"   # coral — between red and orange
SILVER   = "\033[38;5;250m"   # light silver-grey
SMOKE    = "\033[38;5;240m"   # mid smoke-grey
BG_BLK   = "\033[40m"

# ── ASCII world map (72 × 20) ───────────────────────────────────────────────────
# ▓ = land  ' ' = ocean   Last 3 rows are Antarctica.
# Generated from continental bounding-box polygons; each column ≈ 5° longitude,
# each row ≈ 9° latitude (90 N at top, 90 S at bottom).
_WORLD_MAP_ROWS = [
    "                     ▓▓▓▓▓▓▓▓▓▓▓▓▓                                      ",
    "                     ▓▓▓▓▓▓▓▓▓▓▓▓▓        ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓       ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓▓▓                   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "           ▓▓▓▓▓▓▓▓▓▓▓▓         ▓▓           ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓      ",
    "           ▓▓▓▓▓     ▓▓         ▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓      ",
    "           ▓▓▓▓▓                ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓▓▓▓▓▓        ",
    "            ▓▓▓▓         ▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    ▓▓▓▓▓▓          ",
    "            ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓    ▓▓▓▓▓▓          ",
    "                   ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓       ▓▓▓▓▓▓▓▓          ",
    "                   ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓           ▓▓▓▓▓▓▓▓▓     ",
    "                   ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓           ▓▓▓▓▓▓▓▓▓     ",
    "                   ▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓           ▓▓▓▓▓▓▓▓▓  ▓▓▓",
    "                    ▓▓▓▓                                  ▓▓▓▓▓▓▓▓▓  ▓▓▓",
    "                    ▓▓▓▓                                             ▓▓▓",
    "                    ▓▓▓▓                                                ",
    "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
]
_MAP_W = 72   # columns in the base map
_MAP_H = 20   # rows in the base map

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


def _progress_bar(fraction: float, width: int = 24,
                  fill_color: str = GREEN, empty_color: str = SMOKE) -> str:
    """ASCII progress bar using block characters.
    fraction = 0.0–1.0 ; width = number of cells."""
    fraction = max(0.0, min(1.0, fraction))
    filled   = round(fraction * width)
    empty    = width - filled
    return f"{fill_color}{'█' * filled}{RST}{empty_color}{'░' * empty}{RST}"


def _latency_color(ms_str: str):
    """Return a colour that transitions green→yellow→amber→orange→red with latency."""
    try:
        ms = float(ms_str)
    except (ValueError, TypeError):
        return DIM
    if ms < 30:   return LIME
    if ms < 60:   return GREEN
    if ms < 100:  return GOLD
    if ms < 150:  return AMBER
    if ms < 200:  return ORANGE
    return RED


def _print_map_box(lat=None, lon=None, location=""):
    """
    Render the ASCII world map inside a decorative box and print it to stdout.
    The map is scaled to fit the current terminal width.
    A ◉ marker is placed at (lat, lon) if provided.
    """
    w        = _tw()
    inner    = w - 4
    # map cells fit between the 2 border chars and 2-space padding each side
    map_area = max(1, inner - BOX_PADDING)   # visible chars inside ║…║ for map

    # Scale map width to available space
    mw = min(_MAP_W, map_area)
    mh = _MAP_H

    if mw < _MAP_W:
        scaled = []
        for orig_row in _WORLD_MAP_ROWS:
            new_row = []
            for c in range(mw):
                oc = int(c / mw * _MAP_W)
                new_row.append(orig_row[oc] if oc < len(orig_row) else " ")
            scaled.append("".join(new_row))
    else:
        scaled = list(_WORLD_MAP_ROWS)

    # Marker position
    mr = mc = -1
    if lat is not None and lon is not None:
        mr = max(0, min(mh - 1, int((90 - lat) / 180 * mh)))
        mc = max(0, min(mw - 1, int((lon + 180) / 360 * mw)))

    # ── Title bar ───────────────────────────────────────────────────────────
    loc_part = f"  ◉ {location}" if location else ""
    title    = f"  WORLD MAP{loc_part}  "
    title_pad = max(0, inner - BOX_PADDING - len(title))

    print(f"\n  {CYAN}{BOLD}╔{'═' * inner}╗{RST}")
    print(f"  {CYAN}{BOLD}║{RST}  {BOLD}{AQUA}{title}{RST}"
          f"{' ' * title_pad}  {CYAN}{BOLD}║{RST}")
    print(f"  {CYAN}{BOLD}╠{'─' * inner}╣{RST}")

    # ── Map rows ────────────────────────────────────────────────────────────
    for ri, row_str in enumerate(scaled):
        rendered = ""
        for ci, ch in enumerate(row_str):
            if ri == mr and ci == mc:
                rendered += f"{BOLD}{RED}◉{RST}"
            elif ch == "▓":
                if ri >= mh - 3:                         # Antarctica — silver
                    rendered += f"{DIM}{SILVER}▓{RST}"
                else:
                    rendered += f"{TEAL}▓{RST}"          # land — teal
            else:
                rendered += f"{DIM}{SMOKE}·{RST}"        # ocean — dim dots
        right_pad = map_area - mw
        print(f"  {CYAN}{BOLD}║{RST}  {rendered}{' ' * right_pad}  {CYAN}{BOLD}║{RST}")

    # ── Coordinates line ────────────────────────────────────────────────────
    if lat is not None and lon is not None:
        ns = "N" if lat >= 0 else "S"
        ew = "E" if lon >= 0 else "W"
        coord_txt  = f"  lat {abs(lat):.2f}°{ns}  ·  lon {abs(lon):.2f}°{ew}  "
        coord_pad  = max(0, inner - BOX_PADDING - len(coord_txt))
        print(f"  {CYAN}{BOLD}╠{'─' * inner}╣{RST}")
        print(f"  {CYAN}{BOLD}║{RST}  {DIM}{SILVER}{coord_txt}{RST}"
              f"{' ' * coord_pad}  {CYAN}{BOLD}║{RST}")

    print(f"  {CYAN}{BOLD}╚{'═' * inner}╝{RST}")


# ── Animated spinner (for data-collection phases) ──────────────────────────────
class Spinner:
    """
    Draws a braille spinner in-place while a long operation runs.
    Usage:
        with Spinner("Gathering data…"):
            do_slow_stuff()
    The spinner auto-erases itself when the context exits.
    """
    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, msg: str = ""):
        self._msg  = msg
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

    def _spin(self):
        i = 0
        width = len(self._msg) + 8
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            print(f"\r  {AQUA}{BOLD}{frame}{RST}  {DIM}{SILVER}{self._msg}{RST}",
                  end="", flush=True)
            i += 1
            time.sleep(0.08)
        # Erase the spinner line
        print(f"\r{' ' * (width + 4)}\r", end="", flush=True)

    def __enter__(self):
        self._t = threading.Thread(target=self._spin, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._t:
            self._t.join(timeout=0.5)

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
    label_col = f"{BOLD}{SILVER}{label:<22}{RST}"
    print(f"{pad}  {DIM}{AQUA}›{RST}  {label_col}  {color}{value}{RST}")


def section(title, icon=""):
    """Jarvis-style section divider with accent glow line."""
    w       = _tw()
    icon_s  = f"{icon} " if icon else ""
    heading = f"{BOLD}{AQUA}{icon_s}{title}{RST}"
    prefix  = f"  {DIM}{CYAN}◈{RST}  "
    used    = _vis(prefix) + _vis(heading) + 4
    fill    = max(2, w - used)
    line    = f"{DIM}{SMOKE}{'─' * fill}{RST}"
    print(f"\n{prefix}{heading}  {line}")


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


# ── WireGuard interface auto-detection ────────────────────────────────────────
def detect_wg_interface():
    """
    Detect the active WireGuard interface by running `sudo wg show interfaces`.
    Returns the first interface found, or falls back to 'wg0' if none is active
    or the command is unavailable.
    """
    try:
        out = subprocess.check_output(
            ["sudo", "wg", "show", "interfaces"],
            text=True, stderr=subprocess.DEVNULL, timeout=5)
        ifaces = out.strip().split()
        if ifaces:
            return ifaces[0]
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, PermissionError, OSError):
        pass
    return "wg0"


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
                proton, vpn_asn, std, adv, lat=None, lon=None):

    print("\033[2J\033[H", end="")
    utc, loc = now_str()
    w     = _tw()
    inner = w - 4

    # ── Header box ─────────────────────────────────────────────────────────────
    t1 = (f"{BOLD}{AQUA}⬡{RST}  {BOLD}{WHITE}PROTONWG-SENTINEL{RST}"
          f"  {DIM}{SMOKE}─── WireGuard + ProtonVPN Monitor ─── v{VERSION}{RST}")
    t2 = f"  {DIM}{SILVER}🕐  {utc}  {SMOKE}·{RST}  {DIM}{SILVER}{loc}{RST}"
    t3 = (f"  {DIM}{SMOKE}Enter{RST}{DIM} → fresh report"
          f"  {SMOKE}·{RST}  {DIM}Ctrl-C → quit{RST}")
    print(f"\n{_box_top(inner, INDIGO)}")
    print(_box_row(t1, inner, INDIGO))
    print(_box_row(t2, inner, INDIGO))
    print(_box_mid(inner, INDIGO))
    print(_box_row(t3, inner, INDIGO))
    print(f"{_box_bot(inner, INDIGO)}")

    # ── World map ──────────────────────────────────────────────────────────────
    location_str = ""
    if ip_api_d:
        city = ip_api_d.get("city", "")
        cc   = ip_api_d.get("countryCode", "")
        if city and cc:
            location_str = f"{city}, {cc}"
    _print_map_box(lat, lon, location_str)

    # ── WireGuard ──────────────────────────────────────────────────────────────
    section(f"WIREGUARD  [{INTERFACE}]", "🔒")
    lvl  = wg["level"]
    wg_c = (LIME  if lvl == "ok"
            else AMBER if lvl == "stale"
            else ROSE  if lvl == "never"
            else RED)
    wg_i = "✅" if lvl == "ok" else ("⚠️ " if lvl == "stale" else "❌")
    print(f"  {wg_i}  {wg_c}{BOLD}{wg['msg']}{RST}")

    if ping_r["ok"]:
        lat_c = _latency_color(ping_r["latency_ms"])
        try:
            lat_frac = min(1.0, float(ping_r["latency_ms"]) / 200)
        except (ValueError, TypeError):
            lat_frac = 0.0
        bar = _progress_bar(lat_frac, width=16, fill_color=lat_c, empty_color=SMOKE)
        print(f"  📡  {BOLD}{SILVER}Endpoint:{RST}  {DIM}{ping_r['endpoint']}{RST}"
              f"   {lat_c}{BOLD}{ping_r['latency_ms']} ms{RST}  {bar}")
    else:
        print(f"  📡  {BOLD}{SILVER}Endpoint ping:{RST}  {DIM}{ping_r['msg']}{RST}")

    # WG config inline
    for line in wg_config.get("info", []):
        print(f"  {LIME}✓{RST}  {DIM}{GREEN}{line}{RST}")
    for line in wg_config.get("warnings", []):
        c = AMBER if ("split-tunnel" in line.lower()
                      or "unreadable" in line.lower()) else CORAL
        print(f"  {AMBER}⚠{RST}  {c}{line}{RST}")
    if not wg_config.get("info") and not wg_config.get("warnings"):
        print(f"  {DIM}No WireGuard config data retrieved{RST}")

    # ── Network / IP ───────────────────────────────────────────────────────────
    section("NETWORK & LOCATION", "🌐")

    pc = (LIME  if proton["level"] == "owned"
          else AMBER if proton["level"] == "partner"
          else RED)
    pi = ("✅" if proton["level"] == "owned"
          else "🟠" if proton["level"] == "partner" else "❌")

    row("IPv4 exit", ipv4 or "not detected", AQUA if ipv4 else RED)
    row("IPv6 exit", ipv6 or "not detected", TEAL if ipv6 else DIM)
    print(f"\n  {pi}  {BOLD}{WHITE}ProtonVPN:{RST}  {pc}{proton['msg']}{RST}")

    # Consolidate location from all three sources
    country  = (ip_api_d.get("country","")     or ipwho_d.get("country","")
                or ipinf_d.get("country","")   or "?")
    city2    = (ip_api_d.get("city","")        or ipwho_d.get("city","")
                or ipinf_d.get("city","")      or "?")
    region   = (ip_api_d.get("regionName","")  or ipwho_d.get("region","")
                or ipinf_d.get("region","")    or "?")
    timezone = (ip_api_d.get("timezone","")    or ipinf_d.get("timezone","") or "?")
    isp      = (ip_api_d.get("isp","")         or
                (ipwho_d.get("connection") or {}).get("isp","") or "?")
    asn_str  = (ip_api_d.get("as","")          or ipinf_d.get("org","")
                or str((ipwho_d.get("connection") or {}).get("asn","?")) or "?")

    print()
    row("Country",  f"{country}  ·  {city2}, {region}", SILVER)
    row("Timezone", timezone, DIM)
    row("ISP",      isp,      SILVER)
    row("ASN",      asn_str,  AQUA)
    if lat is not None and lon is not None:
        ns = "N" if lat >= 0 else "S"
        ew = "E" if lon >= 0 else "W"
        row("Coordinates", f"{abs(lat):.2f}°{ns}  ·  {abs(lon):.2f}°{ew}", DIM)

    # ── Routing & Kill Switch ──────────────────────────────────────────────────
    section("ROUTING & KILL SWITCH", "🛡")

    if routing["default_via_vpn"]:
        note = (f"  {DIM}{SMOKE}{routing['warning']}{RST}"
                if routing.get("warning") else "")
        print(f"  ✅  {LIME}Default route via {BOLD}{INTERFACE}{RST}{LIME} ✓{RST}{note}")
    else:
        print(f"  ❌  {RED}{BOLD}{routing.get('warning') or f'Default route not through VPN'}{RST}")

    if ks["active"]:
        print(f"  ✅  {LIME}Kill switch active{RST}  {DIM}—  {ks['details']}{RST}")
    else:
        ks_c = AMBER if "unavailable" in ks["details"].lower() else CORAL
        print(f"  ⚠️   {ks_c}Kill switch: {ks['details']}{RST}")

    # ── DNS leak ───────────────────────────────────────────────────────────────
    section("DNS LEAK TEST", "🔍")

    def show_dns(label, resolvers):
        level, summary = assess_dns(resolvers, vpn_asn)
        ic = "✅" if level == "ok" else ("⚠️ " if level == "warn" else "❌")
        co = LIME if level == "ok" else (AMBER if level == "warn" else RED)
        print(f"\n  {BOLD}{SILVER}{label}{RST}")
        print(f"  {ic}  {co}{summary}{RST}")
        for r in resolvers:
            ip_r  = r.get("ip", "?")
            isp_r = r.get("isp") or "?"
            cc_r  = r.get("country_code", "?")
            if is_proton_internal(ip_r):
                tag = f"  {LIME}← ProtonVPN internal tunnel DNS ✓{RST}"
            elif ip_r in KNOWN_SAFE_DNS_IPS:
                tag = f"  {MINT}← known-safe public DNS ✓{RST}"
            elif vpn_asn in PROTON_OWNED_ASN | PROTON_PARTNER_ASN:
                tag = f"  {LIME}← Proton network ✓{RST}"
            elif any(kw in isp_r.lower() for kw in PROTON_DNS_KW):
                tag = f"  {LIME}← Proton DNS ✓{RST}"
            else:
                tag = f"  {RED}← possible leak — not Proton DNS{RST}"
            print(f"      {DIM}›{RST}  {AQUA}{ip_r:<42}{RST}  {DIM}{isp_r} [{cc_r}]{RST}{tag}")

    show_dns("Standard check  —  ipleak.net API", std)
    show_dns("Advanced check  —  bash.ws  (same engine as dnsleaktest.com Extended Test)", adv)
    print(f"\n  {DIM}Manual check:{RST}  {DIM}https://www.dnsleaktest.com → Extended Test{RST}")

    # ── System ─────────────────────────────────────────────────────────────────
    section("SYSTEM", "🖥 ")
    print(f"  {DIM}{SILVER}{sys_info['hostname']}  ·  {sys_info['os']}"
          f"  ·  {sys_info['arch']}  ·  Python {sys_info['python']}{RST}")

    # ── Footer ─────────────────────────────────────────────────────────────────
    print(f"\n{DIM}{SMOKE}{'─' * w}{RST}")
    print(f"  {DIM}{SMOKE}Switching to compact dashboard in {RST}"
          f"{BOLD}{SILVER}3s{RST}{DIM}{SMOKE}  ·  "
          f"Press {RST}{BOLD}{SILVER}Enter{RST}{DIM}{SMOKE} to repeat this report{RST}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  RENDER — Compact live status (shown between full reports)
# ══════════════════════════════════════════════════════════════════════════════
def render_compact(wg, ping_r, routing, ks, ipv4, ipv6,
                   proton, vpn_asn, std, adv, last_full_utc, next_full_in,
                   location="", lat=None, lon=None):
    """
    Single-screen Jarvis-style dashboard:
      • Full-width status banner (colour = overall health)
      • ASCII world map with VPN exit marker
      • Compact check rows
      • Progress bar for next full re-check
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
        bdr_c      = LIME
        banner_txt = (f"  {BOLD}{LIME}⬡  PROTECTED{RST}  {DIM}{SMOKE}────{RST}  "
                      f"{LIME}ProtonVPN WireGuard tunnel is SECURE{RST}")
    elif any_red:
        bdr_c      = RED
        banner_txt = (f"  {BOLD}{RED}⬡  ALERT{RST}  {DIM}{SMOKE}────{RST}  "
                      f"{CORAL}VPN issue detected — check details below{RST}")
    else:
        bdr_c      = AMBER
        banner_txt = (f"  {BOLD}{AMBER}⬡  DEGRADED{RST}  {DIM}{SMOKE}────{RST}  "
                      f"{AMBER}Some checks need attention{RST}")

    # ── Status banner ──────────────────────────────────────────────────────────
    print(f"\n{_box_top(inner, bdr_c)}")
    print(_box_row(banner_txt, inner, bdr_c))
    print(f"{_box_bot(inner, bdr_c)}")

    # ── World map ──────────────────────────────────────────────────────────────
    _print_map_box(lat, lon, location)

    # ── Check rows ─────────────────────────────────────────────────────────────
    print(f"\n  {DIM}{SMOKE}{'─' * (w - 4)}{RST}")

    def _crow(icon, label, color, value):
        lbl = f"{BOLD}{SILVER}{label:<18}{RST}"
        print(f"  {icon}  {lbl}  {color}{value}{RST}")

    # WireGuard
    wg_c  = (LIME  if lvl == "ok"
              else AMBER if lvl == "stale"
              else CORAL if lvl == "never"
              else RED)
    wg_ic = "✅" if lvl == "ok" else ("⚠️ " if lvl == "stale" else "❌")
    _crow(wg_ic, "WireGuard", wg_c, wg["msg"])

    # Latency
    if ping_r["ok"]:
        lat_c = _latency_color(ping_r["latency_ms"])
        try:
            lat_frac = min(1.0, float(ping_r["latency_ms"]) / 200)
        except (ValueError, TypeError):
            lat_frac = 0.0
        bar = _progress_bar(lat_frac, width=10, fill_color=lat_c, empty_color=SMOKE)
        _crow("📡", "Latency",
              lat_c,
              f"{BOLD}{ping_r['latency_ms']} ms{RST}  {bar}  "
              f"{DIM}{ping_r['endpoint']}{RST}")
    else:
        _crow("📡", "Latency", DIM, ping_r["msg"])

    # Exit IPs
    _crow("🌐", "Exit IPv4",  AQUA if ipv4 else RED, ipv4 or "not detected")
    if ipv6:
        _crow("🌐", "Exit IPv6", TEAL, ipv6)

    # ProtonVPN ASN
    pc = (LIME  if proton["level"] == "owned"
          else AMBER if proton["level"] == "partner"
          else RED)
    pi = ("✅" if proton["level"] == "owned"
          else "🟠" if proton["level"] == "partner" else "❌")
    _crow(pi, "ProtonVPN", pc, proton["msg"])

    # Location
    if location:
        _crow("📍", "Location", SILVER, location)

    # Default route
    r_ic  = "✅" if route_ok else "❌"
    r_c   = LIME if route_ok else RED
    r_msg = (f"Default route via {INTERFACE} ✓" if route_ok
             else (routing.get("warning") or f"Not routed via {INTERFACE}"))
    _crow(r_ic, "Route", r_c, r_msg)

    # Kill switch
    ks_ic = "✅" if ks["active"] else "⚠️ "
    ks_c  = LIME if ks["active"] else AMBER
    _crow(ks_ic, "Kill switch", ks_c, ks["details"])

    # DNS
    for dns_lbl, dns_lvl2, dns_msg in (
        ("DNS standard", std_lvl, assess_dns(std, vpn_asn)[1]),
        ("DNS advanced", adv_lvl, assess_dns(adv, vpn_asn)[1]),
    ):
        d_ic = "✅" if dns_lvl2 == "ok" else ("⚠️ " if dns_lvl2 == "warn" else "❌")
        d_c  = LIME if dns_lvl2 == "ok" else (AMBER if dns_lvl2 == "warn" else RED)
        _crow(d_ic, dns_lbl, d_c, dns_msg)

    print(f"  {DIM}{SMOKE}{'─' * (w - 4)}{RST}")

    # ── Progress bar + timestamps ───────────────────────────────────────────────
    elapsed_frac = max(0.0, 1.0 - next_full_in / max(1, FULL_INTERVAL))
    bar_color    = TEAL if all_green else (CORAL if any_red else AMBER)
    prog_bar     = _progress_bar(elapsed_frac, width=inner - 20,
                                 fill_color=bar_color, empty_color=SMOKE)
    bar_label    = f"{DIM}{SMOKE}next check {RST}{BOLD}{SILVER}{next_full_in}s{RST}"
    print(f"\n  {prog_bar}  {bar_label}")
    print(f"  {DIM}{SMOKE}🕐  {utc}  ·  {loc}{RST}")
    print(f"  {DIM}{SMOKE}📋  Last: {RST}{BOLD}{SILVER}{last_full_utc}{RST}"
          f"  {DIM}·  Enter → full report   ·  Ctrl-C → quit{RST}\n")


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
    # Extract lat/lon for the world map marker
    try:
        lat = float(ip_api_d.get("lat")) if ip_api_d.get("lat") is not None else None
    except (ValueError, TypeError):
        lat = None
    try:
        lon = float(ip_api_d.get("lon")) if ip_api_d.get("lon") is not None else None
    except (ValueError, TypeError):
        lon = None
    return dict(ipv4=ipv4, ipv6=ipv6, ip_api_d=ip_api_d, ipinf_d=ipinf_d,
                ipwho_d=ipwho_d, vpn_asn=vpn_asn, proton=proton,
                std=std, adv=adv, location=location, lat=lat, lon=lon)


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
        "provider":     ASN_LABELS.get(vpn_asn, (vpn_asn, "?"))[0],
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
    global _running, INTERFACE

    signal.signal(signal.SIGINT,
                  lambda s, f: (print(f"\n{DIM}protonwg-sentinel stopped.{RST}\n"),
                                sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    # Auto-detect the active WireGuard interface (overrides module-level default)
    INTERFACE = detect_wg_interface()

    sys_info = get_system()

    # Start Enter-key listener thread
    listener = threading.Thread(target=_enter_listener, daemon=True)
    listener.start()

    # ── Boot splash ────────────────────────────────────────────────────────────
    print("\033[2J\033[H", end="")
    w     = _tw()
    inner = w - 4

    # Jarvis-style boot banner
    _banner_lines = [
        f"  {BOLD}{AQUA}┌─┐┬─┐┌─┐┌┬┐┌─┐┌┐┌┬ ┬┌─┐{RST}  {BOLD}{WHITE}╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦{RST}",
        f"  {BOLD}{AQUA}├─┘├┬┘│ │ │ │ ││││││││ ┬{RST}  {BOLD}{WHITE}╚═╗║╣ ║║║ ║ ║║║║║╣ ║{RST}",
        f"  {BOLD}{AQUA}┴  ┴└─└─┘ ┴ └─┘┘└┘└┴┘└─┘{RST}  {BOLD}{WHITE}╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝{RST}",
    ]
    t1 = (f"{BOLD}{AQUA}⬡{RST}  {BOLD}{WHITE}PROTONWG-SENTINEL{RST}"
          f"  {DIM}{SMOKE}─── WireGuard + ProtonVPN Monitor ─── v{VERSION}{RST}")
    print(f"\n{_box_top(inner, INDIGO)}")
    print(_box_row(t1, inner, INDIGO))
    print(_box_mid(inner, INDIGO))
    for bl in _banner_lines:
        print(_box_row(bl, inner, INDIGO))
    print(f"{_box_bot(inner, INDIGO)}\n")

    _steps = [
        ("Fetching public IPv4 / IPv6 addresses",     AQUA),
        ("Querying ip-api.com · ipinfo.io · ipwho.is", TEAL),
        ("Running standard DNS leak check (ipleak.net)", GREEN),
        ("Running advanced DNS leak test (bash.ws)",   GREEN),
        ("Pinging WireGuard endpoint",                 CYAN),
    ]
    print(f"  {DIM}{SMOKE}Initialising — collecting network data (≈ 10 s){RST}\n")
    for step, col in _steps:
        print(f"  {col}{DIM}◈{RST}  {DIM}{SMOKE}{step}…{RST}")
    print()

    with Spinner("Gathering all data — please wait…"):
        data      = collect_all()
        wg        = check_wg(INTERFACE)
        wg_config = check_wg_config(INTERFACE)
        ping_r    = ping_wg_endpoint(INTERFACE)
        routing   = check_routing(INTERFACE)
        ks        = check_killswitch()

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
                data["std"], data["adv"],
                lat=data.get("lat"), lon=data.get("lon"))

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
            w     = _tw()
            inner = w - 4
            t1 = (f"{BOLD}{AQUA}⬡{RST}  {BOLD}{WHITE}PROTONWG-SENTINEL{RST}"
                  f"  {DIM}{SMOKE}─── Re-checking all data ─── v{VERSION}{RST}")
            print(f"\n{_box_top(inner, INDIGO)}")
            print(_box_row(t1, inner, INDIGO))
            print(f"{_box_bot(inner, INDIGO)}\n")

            with Spinner("Re-fetching all network data…"):
                data      = collect_all()
                wg        = check_wg(INTERFACE)
                wg_config = check_wg_config(INTERFACE)
                ping_r    = ping_wg_endpoint(INTERFACE)
                routing   = check_routing(INTERFACE)
                ks        = check_killswitch()

            last_full_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            last_full_ts  = time.time()
            log_connection(data, wg, data["proton"], data["vpn_asn"],
                           assess_dns(data["std"], data["vpn_asn"])[0],
                           assess_dns(data["adv"], data["vpn_asn"])[0])

            render_full(sys_info, wg, wg_config, ping_r, routing, ks,
                        data["ipv4"], data["ipv6"],
                        data["ip_api_d"], data["ipinf_d"], data["ipwho_d"],
                        data["proton"], data["vpn_asn"],
                        data["std"], data["adv"],
                        lat=data.get("lat"), lon=data.get("lon"))
            time.sleep(3)
            continue

        # ── Compact status ─────────────────────────────────────────────────────
        render_compact(wg, ping_r, routing, ks,
                       data["ipv4"], data["ipv6"],
                       data["proton"], data["vpn_asn"],
                       data["std"], data["adv"],
                       last_full_utc, next_full_in,
                       data.get("location", ""),
                       lat=data.get("lat"), lon=data.get("lon"))

        time.sleep(COMPACT_INTERVAL)


if __name__ == "__main__":
    main()
