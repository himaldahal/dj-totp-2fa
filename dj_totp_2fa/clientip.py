"""Client IP resolution that only believes forwarding headers from trusted proxies."""
import ipaddress

from . import conf


def parse_networks(values):
    nets = []
    for v in values or []:
        try:
            nets.append(ipaddress.ip_network(str(v).strip(), strict=False))
        except ValueError:
            continue
    return nets


def _parse_ip(text):
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip


def in_networks(ip_text, nets):
    ip = _parse_ip(ip_text)
    return bool(ip) and any(ip.version == n.version and ip in n for n in nets)


def client_ip(request):
    if request is None:
        return ""
    resolver = conf.get("IP_RESOLVER")
    if resolver:
        return str(resolver(request) or "")
    remote = request.META.get("REMOTE_ADDR", "")
    trusted = parse_networks(conf.get("TRUSTED_PROXIES"))
    if not trusted or not in_networks(remote, trusted):
        parsed = _parse_ip(remote)
        return str(parsed) if parsed else ""
    header = "HTTP_" + conf.get("CLIENT_IP_HEADER").upper().replace("-", "_")
    chain = [p.strip() for p in request.META.get(header, "").split(",") if p.strip()]
    # Walk from the right: the first hop that is not one of our proxies is the real client.
    for hop in reversed(chain):
        parsed = _parse_ip(hop)
        if parsed is None:
            break  # garbage in the chain: stop believing it, fall back to the socket address
        if not in_networks(str(parsed), trusted):
            return str(parsed)
    parsed = _parse_ip(remote)
    return str(parsed) if parsed else ""


def ip_group(ip_text):
    """Key used for limits: IPv4 as is, IPv6 grouped by IPV6_PREFIX (default /64)."""
    ip = _parse_ip(ip_text)
    if ip is None:
        return str(ip_text or "unknown")
    if ip.version == 6:
        prefix = max(16, min(128, int(conf.get("IPV6_PREFIX"))))
        return str(ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False))
    return str(ip)


def anonymize(ip_text):
    ip = _parse_ip(ip_text)
    if ip is None:
        return ""
    prefix = 24 if ip.version == 4 else 48
    net = ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False)
    return str(net.network_address)


def storable_ip(request_or_ip):
    """The IP to put in the database, honouring STORE_IP and ANONYMIZE_IP. None when nothing should be stored."""
    if not conf.get("STORE_IP"):
        return None
    ip = request_or_ip if isinstance(request_or_ip, str) else client_ip(request_or_ip)
    if not ip:
        return None
    return anonymize(ip) if conf.get("ANONYMIZE_IP") else ip


def is_denied(ip_text):
    nets = parse_networks(conf.get("IP_DENYLIST"))
    return bool(nets) and in_networks(ip_text, nets)


def is_allowlisted(ip_text):
    nets = parse_networks(conf.get("IP_ALLOWLIST"))
    return bool(nets) and in_networks(ip_text, nets)
