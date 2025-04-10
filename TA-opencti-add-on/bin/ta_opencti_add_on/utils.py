import datetime
import ipaddress
import re
import uuid

from stix2.canonicalization.Canonicalize import canonicalize

regex_sha512 = r"[0-9a-fA-F]{128}"
regex_sha256 = r"[0-9a-fA-F]{64}"
regex_sha1 = r"[0-9a-fA-F]{40}"
regex_md5 = r"[0-9a-fA-F]{32}"

def get_proxy_config(helper):
    proxy_uri = helper._get_proxy_uri()
    if proxy_uri:
        return {
            "http": proxy_uri,
            "https": proxy_uri
        }
    else:
        return None

def is_ipv6(value):
    """Determine whether the provided string is an IPv6 address or valid IPv6 CIDR."""
    try:
        ipaddress.IPv6Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv4(value):
    """Determine whether the provided string is an IPv4 address or valid IPv4 CIDR."""
    try:
        ipaddress.IPv4Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def get_hash_type(value):
    if re.match(regex_sha512, value):
        return "sha512"
    elif re.match(regex_sha256, value):
        return "sha256"
    elif re.match(regex_sha1, value):
        return "sha1"
    elif re.match(regex_md5, value):
        return "md5"
    else:
        return None

def generate_identity_id(name, identity_class):
    data = {"name": name.lower().strip(), "identity_class": identity_class.lower()}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "identity--" + id

def generate_incident_id(name, created):
    name = name.lower().strip()
    if isinstance(created, datetime.datetime):
        created = created.isoformat()
    data = {"name": name, "created": created}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "incident--" + id


def generate_case_incident_id(name, created):
    name = name.lower().strip()
    if isinstance(created, datetime.datetime):
        created = created.isoformat()
    data = {"name": name, "created": created}
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "case-incident--" + id

def generate_relation_id(
        relationship_type, source_ref, target_ref, start_time=None, stop_time=None
):
    if isinstance(start_time, datetime.datetime):
        start_time = start_time.isoformat()
    if isinstance(stop_time, datetime.datetime):
        stop_time = stop_time.isoformat()

    if start_time is not None and stop_time is not None:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "start_time": start_time,
            "stop_time": stop_time,
        }
    elif start_time is not None:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "start_time": start_time,
        }
    else:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }
    data = canonicalize(data, utf8=False)
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "relationship--" + id