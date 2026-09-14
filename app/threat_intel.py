"""
External Threat Intelligence — Feature 4 gap closure.
Correlates an IP against two REAL, free, publicly maintained threat feeds:

1. Spamhaus DROP list (https://www.spamhaus.org/drop/drop.txt) — netblocks
   leased/stolen by professional spam and cybercrime operations. Free for
   any use, no API key or signup required.

2. Tor Project's exit node list (https://check.torproject.org/exit-addresses)
   — current Tor exit relays. Official, free, no auth required.

Feeds are downloaded once and cached to disk with a 24-hour TTL, both to
be respectful of these free services and to keep analysis fast.
"""

import os
import time
import ipaddress
import requests

CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "threat_intel_cache")
DROP_CACHE_PATH = os.path.join(CACHE_DIR, "spamhaus_drop.txt")
TOR_CACHE_PATH = os.path.join(CACHE_DIR, "tor_exits.txt")
CACHE_TTL_SECONDS = 24 * 60 * 60

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
TOR_EXIT_LIST_URL = "https://check.torproject.org/exit-addresses"

_drop_networks_cache = None
_tor_exits_cache = None


def _is_cache_stale(cache_path):
    if not os.path.exists(cache_path):
        return True
    age_seconds = time.time() - os.path.getmtime(cache_path)
    return age_seconds > CACHE_TTL_SECONDS


def _download_feed(url, cache_path, label):
    """Download a feed and save it to disk. Fails silently (logs, doesn't crash) if offline."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "EmailThreatForensics/1.0"})
        response.raise_for_status()
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        return True
    except requests.RequestException as e:
        print(f"[threat_intel] Warning: could not refresh {label} feed: {e}")
        return False


def refresh_feeds_if_needed():
    """Refresh both feeds if their cache is missing or older than 24 hours."""
    if _is_cache_stale(DROP_CACHE_PATH):
        _download_feed(SPAMHAUS_DROP_URL, DROP_CACHE_PATH, "Spamhaus DROP")
    if _is_cache_stale(TOR_CACHE_PATH):
        _download_feed(TOR_EXIT_LIST_URL, TOR_CACHE_PATH, "Tor exit list")


def _parse_drop_list(text):
    """Spamhaus DROP format: one CIDR netblock per line, comments start with ';'."""
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";")[0].strip()
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _parse_tor_exit_list(text):
    """Tor format: only 'ExitAddress <ip> <date>' lines matter."""
    exits = set()
    for line in text.splitlines():
        if line.startswith("ExitAddress "):
            parts = line.split()
            if len(parts) >= 2:
                exits.add(parts[1])
    return exits


def load_drop_networks():
    global _drop_networks_cache
    if _drop_networks_cache is None:
        if os.path.exists(DROP_CACHE_PATH):
            with open(DROP_CACHE_PATH, "r", encoding="utf-8") as f:
                _drop_networks_cache = _parse_drop_list(f.read())
        else:
            _drop_networks_cache = []
    return _drop_networks_cache


def load_tor_exits():
    global _tor_exits_cache
    if _tor_exits_cache is None:
        if os.path.exists(TOR_CACHE_PATH):
            with open(TOR_CACHE_PATH, "r", encoding="utf-8") as f:
                _tor_exits_cache = _parse_tor_exit_list(f.read())
        else:
            _tor_exits_cache = set()
    return _tor_exits_cache


def check_ip_reputation(ip_address):
    """
    Check an IP against both threat feeds.
    Returns: {"in_spamhaus_drop": bool, "matched_netblock": str|None, "is_tor_exit_node": bool}
    """
    result = {"in_spamhaus_drop": False, "matched_netblock": None, "is_tor_exit_node": False}

    if not ip_address:
        return result

    refresh_feeds_if_needed()

    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return result

    for network in load_drop_networks():
        if ip_obj in network:
            result["in_spamhaus_drop"] = True
            result["matched_netblock"] = str(network)
            break

    if ip_address in load_tor_exits():
        result["is_tor_exit_node"] = True

    return result


if __name__ == "__main__":
    sample_drop = """; Spamhaus DROP List
; Last-Modified: Sun, 13 Sep 2026 00:00:00 GMT
1.10.16.0/20 ; SBL8262
103.216.92.0/24 ; SBL999999
; EOF"""
    sample_tor = """ExitNode ABCDEF1234567890
Published 2026-01-01 00:00:00
LastStatus 2026-01-01 00:00:00
ExitAddress 162.247.72.201 2026-01-01 00:00:00
ExitNode 1234567890ABCDEF
ExitAddress 103.216.92.10 2026-01-01 00:00:00"""

    drop_networks = _parse_drop_list(sample_drop)
    tor_exits = _parse_tor_exit_list(sample_tor)

    print("Parsed DROP networks:", [str(n) for n in drop_networks])
    print("Parsed Tor exits:", tor_exits)

    test_ip = ipaddress.ip_address("103.216.92.10")
    matched = any(test_ip in net for net in drop_networks)
    print(f"Is 103.216.92.10 in DROP list (simulated)? {matched}")
    print(f"Is 103.216.92.10 a Tor exit (simulated)? {'103.216.92.10' in tor_exits}")