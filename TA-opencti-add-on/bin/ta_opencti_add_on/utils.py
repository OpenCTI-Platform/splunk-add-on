import datetime
import hashlib
import ipaddress
import re
import uuid
from stix2.canonicalization.Canonicalize import canonicalize

regex_sha512 = r"[0-9a-fA-F]{128}"
regex_sha256 = r"[0-9a-fA-F]{64}"
regex_sha1 = r"[0-9a-fA-F]{40}"
regex_md5 = r"[0-9a-fA-F]{32}"

def get_proxy_config(helper):
    """
    :param helper:
    :return:
    """
    proxy_uri = helper._get_proxy_uri()
    if proxy_uri:
        return {
            "http": proxy_uri,
            "https": proxy_uri
        }
    else:
        return None

def is_ipv6(value: str):
    """
    Determine whether the provided string is an IPv6 address or valid IPv6 CIDR.
    :param value:
    :return:
    """
    try:
        ipaddress.IPv6Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv4(value: str):
    """
    Determine whether the provided string is an IPv4 address or valid IPv4 CIDR.
    :param value:
    :return:
    """
    try:
        ipaddress.IPv4Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def get_hash_type(value: str):
    """
    :param value:
    :return:
    """
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

def generate_identity_id(name: str, identity_class: str):
    """
    :param name:
    :param identity_class:
    :return:
    """
    data = {"name": name.lower().strip(), "identity_class": identity_class.lower()}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "identity--" + entity_id

def generate_incident_id(name: str, created):
    """
    :param name:
    :param created:
    :return:
    """
    if isinstance(created, datetime.datetime):
        created = created.isoformat()
    data = {"name": name.lower().strip(), "created": created}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "incident--" + entity_id

def generate_sighting_id(
        sighting_of_ref,
        where_sighted_refs,
        first_seen=None,
        last_seen=None,
):
    """
    :param sighting_of_ref:
    :param where_sighted_refs:
    :param first_seen:
    :param last_seen:
    :return:
    """
    if isinstance(first_seen, datetime.datetime):
        first_seen = first_seen.isoformat()
    if isinstance(last_seen, datetime.datetime):
        last_seen = last_seen.isoformat()

    if first_seen is not None and last_seen is not None:
        data = {
            "type": "sighting",
            "sighting_of_ref": sighting_of_ref,
            "where_sighted_refs": where_sighted_refs,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    elif first_seen is not None:
        data = {
            "type": "sighting",
            "sighting_of_ref": sighting_of_ref,
            "where_sighted_refs": where_sighted_refs,
            "first_seen": first_seen,
        }
    else:
        data = {
            "type": "sighting",
            "sighting_of_ref": sighting_of_ref,
            "where_sighted_refs": where_sighted_refs,
        }
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "sighting--" + entity_id

def generate_case_incident_id(name: str, created):
    """
    :param name:
    :param created:
    :return:
    """
    name = name.lower().strip()
    if isinstance(created, datetime.datetime):
        created = created.isoformat()
    data = {"name": name, "created": created}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "case-incident--" + entity_id

def generate_relation_id(
        relationship_type,
        source_ref,
        target_ref,
        start_time=None,
        stop_time=None
):
    """
    :param relationship_type:
    :param source_ref:
    :param target_ref:
    :param start_time:
    :param stop_time:
    :return:
    """
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
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "relationship--" + entity_id


# Result fields that differ between runs of the same search even when the
# underlying event is identical. They must not feed the event identity key.
#   rid            row index injected by pre_handle() (0 for per-result alerts)
#   info_*         added by `addinfo` (search window, search time, sid)
#   search_now     scheduler dispatch time
#   orig_sid/rid   ES notable / summary-index provenance
def event_identity_key(event):
    """
    Build a key that identifies the underlying Splunk event, independent of the
    search run that returned it (#44).

    Scheduled searches with overlapping windows (e.g. every 5m over the last
    15m) return the same event in several runs, each with a different sid and
    row position. The key must be the same in every run so the resulting
    incident keeps being upserted instead of duplicated.

    Resolution order:
      1. _bkt (or index + splunk_server) + _cd  Splunk's address of an indexed event
      2. _raw                         raw event text when _cd was dropped

    Rows from transforming searches (stats, table, ...) carry neither, and are
    deliberately not keyed: their field values (counts, etc.) can change between
    overlapping runs, so any content hash would give the same logical row a new
    ID each run. They keep the legacy name + _time behaviour (upsert across
    runs; same-second collisions remain possible for them).

    :param event: the current result dict
    :return: str key ("" for rows without _cd/_raw)
    """
    cd = event.get("_cd")
    if cd:
        # _bkt ("index~id~origin_guid") is stable across cluster peers; fall back
        # to index + splunk_server when the search did not keep it
        bkt = event.get("_bkt")
        if bkt:
            return "cd|{}|{}".format(bkt, cd)
        return "cd|{}|{}|{}".format(event.get("index", ""), event.get("splunk_server", ""), cd)
    raw = event.get("_raw")
    if raw:
        return "raw|{}".format(raw)
    return ""


def disambiguate_created(event_date, event):
    """
    Add a deterministic sub-second offset to an event date when Splunk's _time
    only has whole-second resolution (#44).

    Incident and Case-Incident IDs are derived from name + created, so distinct
    alert results firing in the same second would otherwise collapse onto one
    OpenCTI entity. The offset (1-999 ms) is derived from event_identity_key(),
    so the same event yields the same timestamp - and the same ID - on retries
    and across overlapping scheduled-search runs, preserving the upsert
    behaviour. Distinct same-second events land on different offsets with high
    probability (hash into 999 slots; ~0.1% collision chance for two events).
    The offset is never 0, so a disambiguated ID never equals the legacy one.

    :param event_date: datetime built from event["_time"]
    :param event: the current result dict
    :return: datetime (unchanged when _time is absent, has sub-second
             precision, or the row has no _cd/_raw - e.g. transforming
             searches, which keep the legacy created)
    """
    raw_time = event.get("_time")
    if not raw_time:
        return event_date
    try:
        epoch = float(raw_time)
    except (TypeError, ValueError):
        return event_date
    if epoch != int(epoch) or event_date.microsecond != 0:
        return event_date

    key = event_identity_key(event)
    if not key:
        return event_date
    digest = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
    offset_ms = 1 + digest % 999
    return event_date + datetime.timedelta(milliseconds=offset_ms)
