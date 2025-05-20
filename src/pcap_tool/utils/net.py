import ipaddress


def anonymize_ip(ip_str: str) -> str:
    """Return a network-only representation of ``ip_str``.

    IPv4 addresses are zeroed to /24 and IPv6 addresses to /48.
    """
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.IPv4Network(f"{addr}/24", strict=False)
    else:
        net = ipaddress.IPv6Network(f"{addr}/48", strict=False)
    return str(net.network_address)
