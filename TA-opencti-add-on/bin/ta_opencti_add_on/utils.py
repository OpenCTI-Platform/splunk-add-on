import ipaddress
import stix2

def is_ipv6(ip_str):
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    try:
        ipaddress.IPv6Address(ip_str)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Network(ip_str, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv4(ip_str):
    """Determine whether the provided string is an IPv4 address or valid IPv4 CIDR."""
    try:
        ipaddress.IPv4Address(ip_str)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(ip_str, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False

def get_marking_id(value):
    #TODO: how to manage TLP:AMBER+STRICT
    if value == "tlp_clear":
        return stix2.TLP_CLEAR
    if value == "tlp_green":
        return stix2.TLP_GREEN
    if value == "tlp_amber":
        return stix2.TLP_AMBER
    if value == "tlp_red":
        return stix2.TLP_RED


def extract_observables_from_cim_model(event):
    observables = []
    if "url" in event:
        observables.append({"type": "url", "value": event.get("url")})
    if "url_domain" in event:
        observables.append({"type": "domain", "value": event.get("url_domain")})
    if "http_user_agent" in event:
        observables.append({"type": "user-agent", "value": event.get("http_user_agent")})
    if "dest_ip" in event:
        if is_ipv4(event.get("dest_ip")):
            observables.append({"type": "ipv4", "value": event.get("dest_ip")})
        if is_ipv6(event.get("dest_ip")):
            observables.append({"type": "ipv6", "value": event.get("dest_ip")})
    if "src_ip" in event:
        if is_ipv4(event.get("src_ip")):
            observables.append({"type": "ipv4", "value": event.get("src_ip")})
        if is_ipv6(event.get("src_ip")):
            observables.append({"type": "ipv6", "value": event.get("src_ip")})

    return observables