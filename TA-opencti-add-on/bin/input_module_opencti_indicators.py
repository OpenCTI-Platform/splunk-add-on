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
    return (
        datetime.utcnow()
        .replace(microsecond=0, tzinfo=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_input(helper, definition):
    pass


def exist_in_kvstore(kv_store, key_id):
    try:
        kv_store.query_by_id(key_id)
        return True
    except:
        return False


def sanitize_key(key):
    return key.replace(".", ":").replace("'", "")


def parse_stix_pattern(stix_pattern):
    try:
        parsed_pattern = Pattern(stix_pattern)
        for observable_type, comparisons in six.iteritems(
            parsed_pattern.inspect().comparisons
        ):
            for data_path, data_operator, data_value in comparisons:
                if observable_type in SUPPORTED_TYPES:
                    data_path = ".".join(data_path)
                    if (
                        data_path in SUPPORTED_TYPES[observable_type]
                        and data_operator == "="
                    ):
                        return {
                            "type": SUPPORTED_TYPES[observable_type][data_path],
                            "value": data_value.strip("'"),
                        }
    except Exception as e:
        print(f"[!] STIX pattern parse error: {e} | pattern = {stix_pattern}")
        return None


def enrich_payload(splunk_helper, payload, msg_event):
    payload["stream_id"] = splunk_helper.get_arg("stream_id")
    payload["input_name"] = splunk_helper.get_input_stanza_names()
    payload["event"] = msg_event

    created_by_id = payload.get("created_by_ref")
    if created_by_id:
        payload["created_by"] = IDENTITY_DEFs.get(created_by_id)

    payload["markings"] = []
    for marking_ref_id in payload.get("object_marking_refs", []):
        marking_value = MARKING_DEFs.get(marking_ref_id)
        if marking_value:
            payload["markings"].append(marking_value)

    parsed_stix = parse_stix_pattern(payload["pattern"])
    if parsed_stix is None:
        return None
    payload["type"] = parsed_stix["type"]
    payload["value"] = parsed_stix["value"]

    if "extensions" in payload:
        for ext in payload["extensions"].values():
            for attr in [
                "id",
                "score",
                "created_at",
                "updated_at",
                "is_inferred",
                "detection",
                "main_observable_type",
            ]:
                if attr in ext:
                    payload["_key" if attr == "id" else attr] = ext[attr]
        del payload["extensions"]

    if "external_references" in payload:
        del payload["external_references"]

    return payload


def enrich_generic_payload(splunk_helper, payload, msg_event):
    payload["stream_id"] = splunk_helper.get_arg("stream_id")
    payload["input_name"] = splunk_helper.get_input_stanza_names()
    payload["event"] = msg_event

    created_by_id = payload.get("created_by_ref")
    if created_by_id:
        payload["created_by"] = IDENTITY_DEFs.get(created_by_id)

    payload["markings"] = []
    for marking_ref_id in payload.get("object_marking_refs", []):
        marking_value = MARKING_DEFs.get(marking_ref_id)
        if marking_value:
            payload["markings"].append(marking_value)

    if "extensions" in payload:
        for ext in payload["extensions"].values():
            for attr in [
                "id",
                "score",
                "created_at",
                "creator_ids",
                "updated_at",
                "is_inferred",
            ]:
                if attr in ext:
                    payload["_key" if attr == "id" else attr] = ext[attr]

    if "external_references" in payload:
        del payload["external_references"]

    return payload


def collect_events(helper, ew):
    helper.set_log_level(helper.log_level)
    input_name = helper.get_input_stanza_names()
    input_type = "kvstore"
    stream_id = helper.get_arg("stream_id")
    target_index = helper.get_arg("index")

    helper.log_info(
        f'type=stream input_name={input_name} message="OpenCTI data input module started"'
    )
    helper.log_info(
        f'type=stream input_name={input_name} input_type={input_type} message="Selected input type"'
    )
    helper.log_info(
        f'type=stream input_name={input_name} stream_id={stream_id} message="Fetching data from OpenCTI"'
    )

    proxies = get_proxy_config(helper)
    opencti_url = helper.get_global_setting("opencti_url")
    opencti_token = helper.get_global_setting("opencti_api_key")
    #
    # Reset Checkpoint
    #
    # helper.delete_check_point(helper.get_input_stanza_names())
    # helper.log_warning("Checkpoint Reset")
    #
    #
    state = helper.get_check_point(input_name)
    if state is None:
        helper.log_info(
            f'type=state input_name={input_name} message="No checkpoint found, initializing new state"'
        )
        import_from = helper.get_arg("import_from")
        recover_until = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        start_date = datetime.utcnow() - timedelta(days=int(import_from))
        start_timestamp = int(datetime.timestamp(start_date)) * 1000
        state = {
            "start_from": str(start_timestamp) + "-0",
            "recover_until": recover_until,
        }
        helper.log_info(
            f'type=state input_name={input_name} message="Initialized new checkpoint state" state={state}'
        )
    else:
        state = json.loads(state)
        helper.log_info(
            f'type=state input_name={input_name} message="Checkpoint state parsed" state={state}'
        )

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
    helper.log_debug(f"Live stream URL: {live_stream_url}")

    kvstore = None
    helper.log_info(
        f'type=stream input_name={input_name} input_type={input_type} message="Processing input type"'
    )
    if input_type == "kvstore":
        try:
            helper.log_debug("Initializing KV Store")
            session_key = helper.context_meta.get("session_key")
            if not session_key:
                raise ValueError("session_key not found in context_meta")
            service = client.connect(token=session_key, app="TA-opencti-add-on")
            helper.log_info("Connected to Splunk KV Store")
            kvstore = service.kvstore[INDICATORS_KVSTORE_NAME].data
        except Exception as e:
            helper.log_error(f"Failed to connect to KV Store: {e}")
            return

    try:
        messages = SSEClient(
            live_stream_url,
            state.get("start_from"),
            headers={
                "authorization": f"Bearer {opencti_token}",
                "listen-delete": "true",
                "no-dependencies": "true",
                "with-inferences": "true",
            },
            verify=VERIFY_SSL,
            proxies=proxies,
        )

        for msg in messages:
            try:
                if msg.event not in ["create", "update", "delete"]:
                    continue

                message_payload = json.loads(msg.data)
                data = message_payload.get("data", {})
                entity_type = data.get("type")

                if entity_type == "identity":
                    IDENTITY_DEFs[data["id"]] = data.get("name", "Unknown")
                elif entity_type == "marking-definition":
                    MARKING_DEFs[data["id"]] = data.get("name", "Unknown")

                parsed_stix = None
                if entity_type == "indicator" and data.get("pattern_type") == "stix":
                    parsed_stix = enrich_payload(helper, data, msg.event)
                    if parsed_stix is not None:
                        helper.log_info(
                            f'type=stream input_name={input_name} message="Processing indicator" event={msg.event} id={msg.id} name="{parsed_stix["name"]}" pattern="{parsed_stix["pattern"]}"'
                        )
                else:
                    parsed_stix = enrich_generic_payload(helper, data, msg.event)
                    if parsed_stix is not None:
                        helper.log_info(
                            f'type=stream input_name={input_name} message="Processing {data["type"]}" event={msg.event} id={msg.id} name="{data["name"]}"'
                        )

                if parsed_stix is None:
                    helper.log_error(f"Could not enrich data for msg {msg.id}")
                    continue

                key = sanitize_key(data.get("id", parsed_stix.get("_key", msg.id)))
                indicator_value = parsed_stix.get("value", "unknown")
                helper.log_info(
                    f'type=stream input_name={input_name} message="Processing indicator value" value="{indicator_value}"'
                )
                helper.log_debug(
                    f'type=stream input_name={input_name} message="Raw event data" data="{data}"'
                )
                if (
                    input_type == "kvstore"
                    and entity_type == "indicator"
                    and data.get("pattern_type") == "stix"
                ):
                    try:
                        if msg.event == "delete":
                            if exist_in_kvstore(kvstore, key):
                                kvstore.data.delete_by_id(parsed_stix["_key"])
                                helper.log_info(
                                    f'type=kvstore input_name={input_name} message="Deleted indicator from KV Store" key="{key}"'
                                )
                        else:
                            parsed_stix["added_at"] = datetime.now(
                                timezone.utc
                            ).strftime("%Y-%m-%dT%H:%M:%SZ")
                            kvstore.batch_save(*[parsed_stix])
                            helper.log_info(
                                f'type=kvstore input_name={input_name} message="Inserted indicator into KV Store" key="{key}"'
                            )
                    except Exception as kv_ex:
                        helper.log_error(
                            f'type=kvstore input_name={input_name} message="KV Store operation failed" error="{kv_ex}"'
                        )
                        continue

                elif input_type == "index":
                    # Robust event_time parsing from updated_at, created_at, or first_seen
                    event_time = datetime.now(timezone.utc).timestamp()
                    ew.write_event(
                        helper.new_event(
                            json.dumps(parsed_stix),
                            time=event_time,
                            host=None,
                            index=target_index,
                            source="opencti",
                            sourcetype=f"opencti:{entity_type}",
                            done=True,
                            unbroken=True,
                        )
                    )
                else:
                    helper.log_warning(
                        f'type=stream input_name={input_name} message="Unknown input_type" input_type={input_type}'
                    )
                    continue

                state["start_from"] = msg.id
                helper.log_info(
                    f'type=state input_name={input_name} message="Checkpoint updated" stream_point={msg.id} recover_until="{state.get("recover_until", "")}"'
                )
                helper.save_check_point(input_name, json.dumps(state))
            except Exception as ex:
                helper.log_debug(
                    f'type=stream input_name={input_name} message="Error processing stream message" error="{ex}" msg_id="{msg.id}"'
                )

    except Exception as ex:
        helper.log_error(
            f'type=stream input_name={input_name} message="Stream processing loop failed" error="{ex}"'
        )
        sys.excepthook(*sys.exc_info())
