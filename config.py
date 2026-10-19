import os
import socket
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("QR-CipherChat")

DEFAULT_PORT = int(os.environ.get("PORT", 8000))

try:
    import psutil  # Optional: gives real adapter names (Wi-Fi / Bluetooth / Hotspot)
except ImportError:  # pragma: no cover - graceful fallback
    psutil = None


def get_primary_ip() -> str:
    """
    Attempts to identify the primary outbound IP address of this machine
    by connecting a temporary UDP socket (no packets are sent).
    Without internet there is no default route, so fall back to the best LAN interface.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # 8.8.8.8 is used as a routing target, no packet is actually transmitted
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        s.close()
        if primary_ip and not primary_ip.startswith("127."):
            return primary_ip
    except Exception:
        pass

    for iface in _scan_interfaces():
        if iface["kind"] != "loopback":
            return iface["ip"]
    return "127.0.0.1"


def _classify(name: str, ip: str) -> tuple[str, str]:
    """Returns (kind, human label) for an adapter based on its name and address."""
    n = name.lower()
    if ip.startswith("127."):
        return "loopback", "This device only"
    if "bluetooth" in n or n.startswith("bnep") or n.startswith("bt-pan") or n.startswith("pan"):
        return "bluetooth", "Bluetooth PAN"
    # Windows Mobile Hotspot is always 192.168.137.1 on a "Local Area Connection* N" adapter
    if ip == "192.168.137.1" or "local area connection*" in n or n.startswith("ap") or "hotspot" in n:
        return "hotspot", "Hotspot (no internet needed)"
    if any(k in n for k in ("wi-fi", "wifi", "wlan", "wireless", "wlp")):
        return "wifi", "Wi-Fi"
    # 192.168.56.x is VirtualBox's default host-only network, often on an adapter just called "Ethernet N"
    if ip.startswith("192.168.56.") or any(k in n for k in ("vethernet", "virtualbox", "vmware", "docker", "wsl", "hyper-v", "tailscale", "zerotier", "vpn")):
        return "virtual", "Virtual / VPN adapter"
    if any(k in n for k in ("ethernet", "eth", "enp", "eno", "lan")):
        return "ethernet", "Ethernet / LAN"
    return "lan", "Network"


def _scan_interfaces() -> list[dict]:
    found = []
    if psutil:
        try:
            stats = psutil.net_if_stats()
            for name, addrs in psutil.net_if_addrs().items():
                if name in stats and not stats[name].isup:
                    continue
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("169.254."):
                        kind, label = _classify(name, a.address)
                        found.append({"ip": a.address, "name": name, "kind": kind, "type": label})
        except Exception as e:
            logger.debug(f"psutil interface scan failed: {e}")

    if not found:
        try:
            _, _, ips = socket.gethostbyname_ex(socket.gethostname())
            for ip in ips:
                if not ip.startswith("169.254."):
                    kind, label = _classify("", ip)
                    found.append({"ip": ip, "name": "", "kind": kind, "type": label})
        except Exception:
            pass

    # Most useful first: hotspot > wifi > bluetooth > ethernet > other > virtual > loopback
    order = {"hotspot": 0, "wifi": 1, "bluetooth": 2, "ethernet": 3, "lan": 4, "virtual": 5, "loopback": 9}
    found.sort(key=lambda i: order.get(i["kind"], 6))
    return found


def get_all_interfaces() -> list[dict]:
    """
    Retrieves all available IPv4 addresses on this host (Wi-Fi, Hotspot, Bluetooth PAN, LAN, Localhost),
    flagging the recommended one.
    """
    interfaces = []
    seen = set()
    primary = get_primary_ip()

    for iface in _scan_interfaces():
        if iface["ip"] in seen:
            continue
        seen.add(iface["ip"])
        iface["is_primary"] = iface["ip"] == primary
        interfaces.append(iface)

    if primary not in seen:
        kind, label = _classify("", primary)
        interfaces.insert(0, {"ip": primary, "name": "", "kind": kind, "type": label, "is_primary": True})
        seen.add(primary)

    if "127.0.0.1" not in seen:
        interfaces.append({"ip": "127.0.0.1", "name": "", "kind": "loopback", "type": "This device only", "is_primary": False})

    interfaces.sort(key=lambda i: not i["is_primary"])
    return interfaces


def has_internet() -> bool:
    """
    True when the OS has a route to the internet. Uses a UDP connect, which only
    consults the routing table - no packet ever leaves this machine.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        s.close()
        return True
    except OSError:
        return False
