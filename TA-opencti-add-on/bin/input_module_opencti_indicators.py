# encoding = utf-8
from datetime import datetime, timezone, timedelta
import json
import splunklib.client as client
from filigran_sseclient import SSEClient
from stix2patterns.v21.pattern import Pattern
import six
from ta_opencti_add_on.utils import get_proxy_config
from ta_opencti_add_on.constants import VERIFY_SSL

import sys

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

SUPPORTED_TYPES = {
    "email-addr": {"value": "email-addr"},
    "email-message": {"value": "email-message"},
    "ipv4-addr": {"value": "ipv4-addr"},
    "ipv6-addr": {"value": "ipv6-addr"},
    "domain-name": {"value": "domain-name"},
    "hostname": {"value": "hostname"},
    "url": {"value": "url"},
    "user-agent": {"value": "user-agent"},
    "file": {"hashes.MD5": "md5", "hashes.SHA-1": "sha1", "hashes.SHA-256": "sha256", "name": "filename"},
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
    parsed_pattern = Pattern(stix_pattern)
    for observable_type, comparisons in six.iteritems(
            parsed_pattern.inspect().comparisons
    ):
        for obj_path, obj_operator, obj_value in comparisons:
            if observable_type in SUPPORTED_TYPES:
                obj_path = ".".join(obj_path)
                if obj_path in SUPPORTED_TYPES[observable_type]:
                    if obj_operator == "=":
                        return {
                            "type": SUPPORTED_TYPES[observable_type][obj_path],
                            "value": obj_value.strip("'")
                        }

def enrich_payload(splunk_helper, payload):

    # add stream id and input name #TODO: check if it's usefull
    payload["stream_id"] = splunk_helper.get_arg('stream_id')
    payload["input_name"] = splunk_helper.get_input_stanza_names()

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

    # parse stix pattern
    parsed_stix = parse_stix_pattern(payload['pattern'])
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


def collect_events(helper, ew):
    """Implement your data collection logic here

    # The following examples get the arguments of this input.
    # Note, for single instance mod input, args will be returned as a dict.
    # For multi instance mod input, args will be returned as a single value.
    opt_stream_id = helper.get_arg('stream_id')
    # In single instance mode, to get arguments of a particular input, use
    opt_stream_id = helper.get_arg('stream_id', stanza_name)

    # get input type
    helper.get_input_type()

    # The following examples get input stanzas.
    # get all detailed input stanzas
    helper.get_input_stanza()
    # get specific input stanza with stanza name
    helper.get_input_stanza(stanza_name)
    # get all stanza names
    helper.get_input_stanza_names()

    # The following examples get options from setup page configuration.
    # get the loglevel from the setup page
    loglevel = helper.get_log_level()
    # get proxy setting configuration
    proxy_settings = helper.get_proxy()
    # get account credentials as dictionary
    account = helper.get_user_credential_by_username("username")
    account = helper.get_user_credential_by_id("account id")
    # get global variable configuration
    global_opencti_url = helper.get_global_setting("opencti_url")
    global_opencti_api_key = helper.get_global_setting("opencti_api_key")

    # The following examples show usage of logging related helper functions.
    # write to the log for this modular input using configured global log level or INFO as default
    helper.log("log message")
    # write to the log using specified log level
    helper.log_debug("log message")
    helper.log_info("log message")
    helper.log_warning("log message")
    helper.log_error("log message")
    helper.log_critical("log message")
    # set the log level for this modular input
    # (log_level can be "debug", "info", "warning", "error" or "critical", case insensitive)
    helper.set_log_level(log_level)

    # The following examples send rest requests to some endpoint.
    response = helper.send_http_request(url, method, parameters=None, payload=None,
                                        headers=None, cookies=None, verify=True, cert=None,
                                        timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()

    # The following examples show usage of check pointing related helper functions.
    # save checkpoint
    helper.save_check_point(key, state)
    # delete checkpoint
    helper.delete_check_point(key)
    # get checkpoint
    state = helper.get_check_point(key)

    # To create a splunk event
    helper.new_event(data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
    """

    # set loglevel
    helper.set_log_level(helper.log_level)

    helper.log_info("OpenCTI data input module start")
    input_name = helper.get_input_stanza_names()

    # connect to splunk
    splunk = None
    try:
        splunk = client.connect(token=helper.context_meta['session_key'], owner="nobody", app="TA-opencti-add-on")
    except Exception as ex:
        helper.log_error(f"an exception occurred while connecting to splunk: {ex}")

    if splunk is None:
        helper.log_error(f"Unable to initialize connection with Splunk, Splunk client is None")
        raise Exception("Unable to initialize connection with Splunk, Splunk client is None")

    # manage kvstore
    indicators_kvstore = "opencti_indicators"
    try:
        # Create KV Store if it doesn't exist
        splunk.kvstore.create(indicators_kvstore)
    except Exception as ex:
        helper.log_info(f"An exception occurred while creating kv_store, {ex}")

    # get proxy setting configuration
    proxies = get_proxy_config(helper)
    helper.log_debug(f"proxy configuration: {proxies}")

    # get connection configuration
    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")

    stream_id = helper.get_arg('stream_id')
    helper.log_info(f"going to fetch data of OpenCTI stream.id: {stream_id}")

    # load kvstore
    kv_store = splunk.kvstore[indicators_kvstore].data

    # get stream state
    state = helper.get_check_point(input_name)
    helper.log_info(f"checkpoint State: {state}")
    if state is None:
        helper.log_info("No state, going to initialize it")
        import_from = helper.get_arg('import_from')
        recover_until =  datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        start_date = datetime.utcnow() - timedelta(days=int(import_from))
        start_date_timestamp = int(datetime.timestamp(start_date)) * 1000
        state = {"start_from": str(start_date_timestamp)+"-0", "recover_until": recover_until}
        helper.log_info(f"Initialized state: {state}")
    else:
        state = json.loads(state)
        helper.log_info(f"State: {state}")

    if "recover_until" in state:
        live_stream_url = opencti_url+"/stream/"+stream_id+ "?recover=" + state.get("recover_until")
    else:
        live_stream_url = opencti_url+"/stream/"+stream_id

    # consume OCTI stream
    try:
        messages = SSEClient(
            live_stream_url,
            state.get("start_from"),
            headers={
                "authorization": "Bearer "+opencti_api_key,
                "listen-delete": "true",
                "no-dependencies": "true",
                "with-inferences": "true",
            },
            verify=VERIFY_SSL,
            proxies=proxies
        )

        for msg in messages:
            if msg.event in ["create", "update", "delete"]:
                data = json.loads(msg.data)["data"]
                if data['type'] == "indicator" and data['pattern_type'] == "stix":
                    parsed_stix = enrich_payload(helper, data)
                    if parsed_stix is None:
                        helper.log_error(f"Unable to process indicator: {data['name']} - {data['pattern']}")
                        continue
                    helper.log_info("processing msg: "+ msg.event +" - "+ msg.id +" - "+parsed_stix['name']+" - "+parsed_stix['pattern'])
                    if msg.event == "create" or msg.event == "update":
                        exist = exist_in_kvstore(kv_store, parsed_stix["_key"])
                        if exist:
                            kv_store.update(parsed_stix["_key"], parsed_stix)
                        else:
                            parsed_stix['added_at'] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            kv_store.insert(parsed_stix)
                    if msg.event == "delete":
                        exist = exist_in_kvstore(kv_store, parsed_stix["_key"])
                        if exist:
                            kv_store.delete_by_id(parsed_stix["_key"])

                if data['type'] == "marking-definition":
                    helper.log_info("processing msg: "+ msg.event +" - "+ msg.id +" - "+data['name']+" - "+data['id'])
                    if msg.event == "create" or msg.event == "update":
                        if data['id'] not in MARKING_DEFs:
                            MARKING_DEFs[data['id']] = data['name']

                if data['type'] == "identity":
                    helper.log_info("processing msg: "+ msg.event +" - "+ msg.id +" - "+data['name']+" - "+data['id'])
                    if msg.event == "create" or msg.event == "update":
                        if data['id'] not in IDENTITY_DEFs:
                            IDENTITY_DEFs[data['id']] = data['name']

                # update checkpoint (take 0:00:00.005544 to update)
                state["start_from"] = msg.id
                helper.save_check_point(input_name, json.dumps(state))
    except Exception as ex:
        helper.log_error(f"Error in ListenStream loop, exit, reason: {ex}")
        sys.excepthook(*sys.exc_info())
