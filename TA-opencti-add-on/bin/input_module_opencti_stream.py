# encoding = utf-8
import json
import sys
from datetime import datetime, timezone, timedelta

import six
import splunklib.client as client
from filigran_sseclient import SSEClient
from stix2patterns.v21.pattern import Pattern

from ta_opencti_add_on.constants import VERIFY_SSL, INDICATORS_KVSTORE_NAME
from ta_opencti_add_on.utils import get_proxy_config

"""
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
"""
"""
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
"""

SUPPORTED_TYPES = {
    "email-addr": {"value": "email-addr"},
    "email-message": {"value": "email-message"},
    "ipv4-addr": {"value": "ipv4-addr"},
    "ipv6-addr": {"value": "ipv6-addr"},
    "domain-name": {"value": "domain-name"},
    "hostname": {"value": "hostname"},
    "url": {"value": "url"},
    "user-agent": {"value": "user-agent"},
    "file": {
        "hashes.MD5": "md5",
        "hashes.SHA-1": "sha1",
        "hashes.SHA-256": "sha256",
        "name": "filename",
    },
}

MARKING_DEFs = {}

IDENTITY_DEFs = {}


def date_now_z():
    """get the current date (UTC)
    :return: current datetime for utc
    :rtype: str
    """
    return (
        datetime.utcnow()
        .replace(microsecond=0, tzinfo=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # stream_id = definition.parameters.get('stream_id', None)
    pass


def exist_in_kvstore(kv_store, key_id):
    """
    :param kv_store:
    :param key_id:
    :return:
    """
    try:
        kv_store.query_by_id(key_id)
        exist = True
    except:
        exist = False
    return exist


def sanitize_key(key):
    """Sanitize key name for Splunk usage

    Splunk KV store keys cannot contain ".". Also, keys containing
    unusual characters like "'" make their usage less convenient
    when writing SPL queries.

    Args:
        key (str): value to sanitize

    Returns:
        str: sanitized result
    """
    return key.replace(".", ":").replace("'", "")


def parse_stix_pattern(stix_pattern):
    """
    :param stix_pattern:
    :return:
    """
    parsed_pattern = Pattern(stix_pattern)
    for observable_type, comparisons in six.iteritems(
        parsed_pattern.inspect().comparisons
    ):
        for data_path, data_operator, data_value in comparisons:
            if observable_type in SUPPORTED_TYPES:
                data_path = ".".join(data_path)
                if data_path in SUPPORTED_TYPES[observable_type]:
                    if data_operator == "=":
                        return {
                            "type": SUPPORTED_TYPES[observable_type][data_path],
                            "value": data_value.strip("'"),
                        }


def enrich_payload(splunk_helper, payload, msg_event):
    """
    :param splunk_helper:
    :param payload:
    :return:
    """
    # add stream id and input name #TODO: check if it's useful
    payload["stream_id"] = splunk_helper.get_arg("stream_id")
    payload["input_name"] = splunk_helper.get_input_stanza_names()
    payload["event"] = msg_event  # Add the msg.event to the payload

    # parse created_by
    splunk_helper.log_debug(f"payload: {payload}")
    created_by_id = payload.get("created_by_ref", None)
    if created_by_id is not None:
        org_name = IDENTITY_DEFs.get(created_by_id, None)
        if org_name is not None:
            payload["created_by"] = org_name

    # parse marking_refs
    for marking_ref_id in payload.get("object_marking_refs", []):
        payload["markings"] = []
        if marking_ref_id is not None:
            marking_value = MARKING_DEFs.get(marking_ref_id, None)
            if marking_value is not None:
                payload["markings"].append(marking_value)

    # parse stix pattern
    parsed_stix = parse_stix_pattern(payload["pattern"])
    if parsed_stix is None:
        return None
    payload["type"] = parsed_stix["type"]
    payload["value"] = parsed_stix["value"]
    payload["value"] = parsed_stix["value"]

    if "extensions" in payload:
        for extension_definition in payload["extensions"].values():
            for attribute_name in [
                "id",
                "score",
                "created_at",
                "updated_at",
                "is_inferred",
                "detection",
                "main_observable_type",
            ]:
                attribute_value = extension_definition.get(attribute_name)
                if attribute_value:
                    if attribute_name == "id":
                        payload["_key"] = attribute_value
                    else:
                        payload[attribute_name] = attribute_value
        # remove extensions
        del payload["extensions"]

    # remove external_references
    if "external_references" in payload:
        del payload["external_references"]

    return payload


def enrich_generic_payload(splunk_helper, payload, msg_event):
    """
    Enrich payload for generic entity types
    :param splunk_helper:
    :param payload:
    :param msg_event:
    :return:
    """
    # add stream id and input name
    payload["stream_id"] = splunk_helper.get_arg("stream_id")
    payload["input_name"] = splunk_helper.get_input_stanza_names()
    payload["event"] = msg_event  # Add the msg.event to the payload

    # parse created_by
    created_by_id = payload.get("created_by_ref", None)
    if created_by_id is not None:
        org_name = IDENTITY_DEFs.get(created_by_id, None)
        if org_name is not None:
            payload["created_by"] = org_name

    # parse marking_refs
    for marking_ref_id in payload.get("object_marking_refs", []):
        payload["markings"] = []
        if marking_ref_id is not None:
            marking_value = MARKING_DEFs.get(marking_ref_id, None)
            if marking_value is not None:
                payload["markings"].append(marking_value)

    if "extensions" in payload:
        for extension_definition in payload["extensions"].values():
            for attribute_name in [
                "id",
                "score",
                "created_at",
                "creator_ids",
                "updated_at",
                "is_inferred",
            ]:
                attribute_value = extension_definition.get(attribute_name)
                if attribute_value:
                    if attribute_name == "id":
                        payload["_key"] = attribute_value
                    else:
                        payload[attribute_name] = attribute_value

    # remove external_references
    if "external_references" in payload:
        del payload["external_references"]

    return payload


def collect_events(helper, ew):
    """Implement your data collection logic here"""

    # Set loglevel
    helper.set_log_level(helper.log_level)

    helper.log_info("OpenCTI data input module start")
    input_name = helper.get_input_stanza_names()

    # Get proxy setting configuration
    proxies = get_proxy_config(helper)
    helper.log_debug(f"proxy configuration: {proxies}")

    # Get connection configuration
    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("token")
    input_type = helper.get_input_type()
    stream_id = helper.get_arg("stream_id")
    target_index = helper.get_arg("index")  # Target index for data
    helper.log_info(f"going to fetch data of OpenCTI stream.id: {stream_id}")

    # Get stream state
    state = helper.get_check_point(input_name)
    helper.log_info(f"checkpoint State: {state}")
    if state is None:
        helper.log_info("No state, going to initialize it")
        import_from = helper.get_arg("import_from")
        recover_until = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        start_date = datetime.utcnow() - timedelta(days=int(import_from))
        start_date_timestamp = int(datetime.timestamp(start_date)) * 1000
        state = {
            "start_from": str(start_date_timestamp) + "-0",
            "recover_until": recover_until,
        }
        helper.log_info(f"Initialized state: {state}")
    else:
        state = json.loads(state)
        helper.log_info(f"State: {state}")

    if "recover_until" in state:
        live_stream_url = (
            opencti_url
            + "/stream/"
            + stream_id
            + "?recover="
            + state.get("recover_until")
        )
    else:
        live_stream_url = opencti_url + "/stream/" + stream_id
    helper.log_debug(f"live_stream_url: {live_stream_url}")

    # Consume OpenCTI stream
    try:
        messages = SSEClient(
            live_stream_url,
            state.get("start_from"),
            headers={
                "authorization": "Bearer " + opencti_api_key,
                "listen-delete": "true",
                "no-dependencies": "true",
                "with-inferences": "true",
            },
            verify=VERIFY_SSL,
            proxies=proxies,
        )

        for msg in messages:
            if msg.event in ["create", "update", "delete"]:
                # Parse the message payload
                message_payload = json.loads(msg.data)
                scope = message_payload.get("scope")
                message = message_payload.get("message")
                origin = message_payload.get("origin")

                # Create the message event
                message_event_data = {
                    "event_id": msg.id,
                    "type": msg.event,
                    "scope": scope,
                    "message": message,
                    "origin": origin,
                }
                ew.write_event(
                    helper.new_event(
                        json.dumps(message_event_data),
                        time=None,
                        host=None,
                        index=target_index,
                        source="opencti_stream",
                        sourcetype="opencti:stream",
                        done=True,
                        unbroken=True,
                    )
                )

                # Process the data in the message
                data = message_payload.get("data", {})
                helper.log_debug(f"Raw data: {data}")
                entity_type = data.get("type")

                if entity_type == "identity":
                    helper.log_info(
                        f"Processing identity: {data['id']} - {data.get('name', 'Unknown')}"
                    )
                    if data["id"] not in IDENTITY_DEFs:
                        IDENTITY_DEFs[data["id"]] = data.get("name", "Unknown")

                if entity_type == "marking-definition":
                    helper.log_info(
                        f"Processing marking-definition: {data['id']} - {data.get('name', 'Unknown')}"
                    )
                    if data["id"] not in MARKING_DEFs:
                        MARKING_DEFs[data["id"]] = data.get("name", "Unknown")

                if entity_type == "indicator" and data.get("pattern_type") == "stix":
                    parsed_stix = enrich_payload(helper, data, msg.event)
                    helper.log_debug(f"Parsed STIX: {parsed_stix}")
                    if parsed_stix is None:
                        helper.log_error(
                            f"Unable to process indicator: {data.get('name', 'Unknown')} - {data.get('pattern', 'Unknown')}"
                        )
                        continue
                    helper.log_info(
                        f"Processing indicator: {msg.event} - {msg.id} - {parsed_stix['name']} - {parsed_stix['pattern']}"
                    )
                    ew.write_event(
                        helper.new_event(
                            json.dumps(parsed_stix),
                            time=None,
                            host=None,
                            index=target_index,
                            source="opencti",
                            sourcetype=f"opencti:{entity_type}",
                            done=True,
                            unbroken=True,
                        )
                    )
                else:
                    # Handle other types of objects
                    enriched_data = enrich_generic_payload(helper, data, msg.event)
                    helper.log_info(
                        f"Processing object: {msg.event} - {msg.id} - {data.get('type', 'Unknown')}"
                    )
                    ew.write_event(
                        helper.new_event(
                            json.dumps(enriched_data),
                            time=None,
                            host=None,
                            index=target_index,
                            source="opencti",
                            sourcetype=f"opencti:{entity_type}",
                            done=True,
                            unbroken=True,
                        )
                    )

                # Update checkpoint
                state["start_from"] = msg.id
                helper.save_check_point(input_name, json.dumps(state))

    except Exception as ex:
        helper.log_error(f"Error in ListenStream loop, exit, reason: {ex}")
        sys.excepthook(*sys.exc_info())
