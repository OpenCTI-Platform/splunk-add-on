import stix2
from datetime import datetime

from stix_constants import CustomObservableUserAgent, CustomObservableText, CustomObjectCaseIncident
from utils import get_hash_type, is_ipv6, is_ipv4
from utils import generate_incident_id, generate_identity_id, generate_relation_id, generate_case_incident_id


def _get_stix_marking_id(value):
    if value == "tlp_clear":
        return stix2.TLP_WHITE
    if value == "tlp_green":
        return stix2.TLP_GREEN
    if value == "tlp_amber":
        return stix2.TLP_AMBER
    if value == "tlp_red":
        return stix2.TLP_RED


def _extract_observables_from_cim_model(event, marking, creator):
    """
    :param event:
    :param marking:
    :param creator:
    :return:
    """
    observables = []
    if "url" in event and event.get("url") != "":
        observables.append({"type": "url", "value": event.get("url")})
    if "url_domain" in event and event.get("url_domain") != "":
        observables.append({"type": "domain", "value": event.get("url_domain")})
    if "user" in event and event.get("user") != "unknown" and event.get("user") != "":
        observables.append({"type": "user_account", "value": event.get("user")})
    if "user_name" in event and event.get("user_name") != "unknown" and event.get("user_name") != "":
        observables.append({"type": "user_account", "value": event.get("user_name")})
    if "user_agent" in event and event.get("user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
    if "http_user_agent" in event and event.get("http_user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
    if "dest" in event and event.get("dest") != "":
        if is_ipv4(event.get("dest")):
            observables.append({"type": "ipv4", "value": event.get("dest")})
        elif is_ipv6(event.get("dest")):
            observables.append({"type": "ipv6", "value": event.get("dest")})
        else:
            observables.append({"type": "hostname", "value": event.get("dest")})
    if "dest_ip" in event and event.get("dest_ip") != "":
        if is_ipv4(event.get("dest_ip")):
            observables.append({"type": "ipv4", "value": event.get("dest_ip")})
        if is_ipv6(event.get("dest_ip")):
            observables.append({"type": "ipv6", "value": event.get("dest_ip")})
    if "src" in event and event.get("src") != "":
        if is_ipv4(event.get("src")):
            observables.append({"type": "ipv4", "value": event.get("src")})
        elif is_ipv6(event.get("src")):
            observables.append({"type": "ipv6", "value": event.get("src")})
        else:
            observables.append({"type": "hostname", "value": event.get("src")})
    if "src_ip" in event and event.get("src_ip") != "":
        if is_ipv4(event.get("src_ip")):
            observables.append({"type": "ipv4", "value": event.get("src_ip")})
        if is_ipv6(event.get("src_ip")):
            observables.append({"type": "ipv6", "value": event.get("src_ip")})
    if "file_hash" in event and event.get("file_hash") != "":
        observables.append({"type": "hash", "value": event.get("file_hash")})
    if "file_name" in event and event.get("file_name") != "":
        observables.append({"type": "file_name", "value": event.get("file_name")})

    return _convert_observables_to_stix(observables, marking, creator)


def _extract_observables_from_key_model(event, marking, creator):
    """
    :param event:
    :param marking:
    :param creator:
    :return:
    """
    observables = []
    prefix = "octi"
    # print the keys and values
    for field in event:
        if field.startswith(prefix):
            for key in ["ip", "url", "domain", "hash", "email_addr",
                        "user_agent", "mutex", "text", "windows_registry_key",
                        "windows_registry_value_type", "directory", "email_message",
                        "file_name", "mac_addr", "user_account"]:
                if field == prefix + "_" + key:
                    if key == "hash":
                        hash_type = get_hash_type(event[field])
                        if hash_type:
                            observables.append({"type": hash_type, "value": event[field]})
                    if key == "ip":
                        ipv4 = is_ipv4(event[field])
                        if ipv4:
                            observables.append({"type": "ipv4", "value": event[field]})
                        ipv6 = is_ipv6(event[field])
                        if ipv6:
                            observables.append({"type": "ipv6", "value": event[field]})
                    else:
                        observables.append({"type": key, "value": event[field]})
    return _convert_observables_to_stix(observables, marking, creator)


def _convert_observables_to_stix(observables, marking, creator):
    stix_observables = []
    customer_properties = {
        "created_by_ref": creator["id"]
    }

    for observable in observables:
        if observable.get("type") == "ipv4":
            stix_observable = stix2.IPv4Address(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "ipv6":
            stix_observable = stix2.IPv6Address(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "url":
            stix_observable = stix2.URL(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "domain":
            stix_observable = stix2.DomainName(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "md5":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"MD5": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha1":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"SHA-1": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha256":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"SHA-256": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha512":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"SHA-512": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "file_name":
            stix_observable = stix2.File(
                name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "email_addr":
            stix_observable = stix2.EmailAddress(
                type="email-addr",
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "user_agent":
            stix_observable = CustomObservableUserAgent(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "mutex":
            stix_observable = stix2.Mutex(
                type="mutex",
                name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "text":
            stix_observable = CustomObservableText(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "windows_registry_key":
            stix_observable = stix2.WindowsRegistryKey(
                key=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "windows_registry_value_type":
            stix_observable = stix2.WindowsRegistryValueType(
                data=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "directory":
            stix_observable = stix2.Directory(
                path=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "email_message":
            stix_observable = stix2.EmailMessage(
                subject=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "mac_addr":
            stix_observable = stix2.MACAddress(
                subject=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "user_account":
            stix_observable = stix2.UserAccount(
                account_login=observable.get("value"),
                display_name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
    return stix_observables


def convert_to_incident_response(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    event_date = datetime.utcfromtimestamp(float(event.get("_time")))

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    # observables extraction
    observable_ref_ids = []
    if alert_params.get("observables_extraction") == "cim_model":
        observables = _extract_observables_from_cim_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)
    if alert_params.get("observables_extraction") == "field_mapping":
        observables = _extract_observables_from_key_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)

    # create incident response case
    stix_case_incident = CustomObjectCaseIncident(
        id=generate_case_incident_id(alert_params.get("name"), event_date),
        name=alert_params.get("name"),
        description=alert_params.get("description"),
        severity=alert_params.get("severity"),
        priority=alert_params.get("priority"),
        labels=alert_params.get("labels"),
        created=event_date,
        external_references=[],
        created_by_ref=stix_author.id,
        object_marking_refs=[marking_id],
        object_refs=observable_ref_ids
    )
    bundle_objects.append(stix_case_incident)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()


def convert_to_incident(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    event_date = datetime.utcfromtimestamp(float(event.get("_time")))

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    # observables extraction
    observable_ref_ids = []
    if alert_params.get("observables_extraction") == "cim_model":
        observables = _extract_observables_from_cim_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)
    if alert_params.get("observables_extraction") == "field_mapping":
        observables = _extract_observables_from_key_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)

    # create incident
    stix_incident = stix2.Incident(
        id=generate_incident_id(alert_params.get("name"), event_date),
        name=alert_params.get("name"),
        created=event_date,
        description=alert_params.get("description"),
        object_marking_refs=[marking_id],
        created_by_ref=stix_author.id,
        external_references=[],
        labels=alert_params.get("labels"),
        allow_custom=True,
        custom_properties={
            "source": event.get("host", "Splunk"),
            "severity": alert_params.get("severity"),
            "incident_type": alert_params.get("type"),
            "first_seen": event_date
        }
    )
    bundle_objects.append(stix_incident)

    for observable_id in observable_ref_ids:
        stix_relation_account = stix2.Relationship(
            id=generate_relation_id(
                "related-to", observable_id, stix_incident.id),
            relationship_type="related-to",
            source_ref=observable_id,
            target_ref=stix_incident.id,
            created_by_ref=stix_author.id)
        bundle_objects.append(stix_relation_account)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()
