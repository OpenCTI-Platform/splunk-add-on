# encoding = utf-8
from datetime import datetime, timezone
import json
import splunklib.client as client
from filigran_sseclient import SSEClient
import time

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

def enrich_payload(splunk_helper, payload):

    # add stream id and input name #TODO: check if it's usefull
    payload["stream_id"] = splunk_helper.get_arg('stream_id')
    payload["input_name"] = splunk_helper.get_input_stanza_names()

    """
    if "type" in payload:
        if (payload["type"] == "indicator" and
                payload["pattern_type"].startswith("stix")):

            translation = stix_translation.StixTranslation()
            # add splunk query
            try:
                response = translation.translate(
                    "splunk", "query", "{}", payload["pattern"]
                )
                payload["splunk_queries"] = response
            except:
                pass

            # add mapped values
            try:
                parsed = translation.translate(
                    "splunk", "parse", "{}", payload["pattern"]
                )
                if "parsed_stix" in parsed and len(parsed["parsed_stix"]) > 0:
                    payload["mapped_values"] = []
                    for value in parsed["parsed_stix"]:
                        formatted_value = {}
                        formatted_value[sanitize_key(value["attribute"])] = value[
                            "value"
                        ]
                        payload["mapped_values"].append(formatted_value)
                else:
                    raise ValueError("Not parsed")
            except:
                try:
                    splitted = payload["pattern"].split(" = ")
                    key = sanitize_key(splitted[0].replace("[", ""))
                    value = splitted[1].replace("'", "").replace("]", "")
                    formatted_value = {}
                    formatted_value[key] = value
                    payload["mapped_values"] = [formatted_value]
                except:
                    payload["mapped_values"] = []

            # add values
            payload["values"] = sum(
                [list(value.values()) for value in payload["mapped_values"]], []
            )
        created_by = payload.get("created_by_ref", None)
        if created_by is not None:
            org_name = self.get_org_name(created_by)
            if org_name is not None:
                payload["created_by"] = org_name
    """
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
    loglevel = helper.get_log_level()
    helper.set_log_level(loglevel)

    helper.log_info("OpenCTI data input module")
    input_name = helper.get_input_stanza_names()

    # connect to splunk
    splunk = None
    try:
        splunk = client.connect(token=helper.context_meta['session_key'], owner="nobody", app="TA-opencti-add-on")
    except Exception as ex:
        helper.log(f"An exception occurred while connecting to splunk: {ex}")

    if splunk is None:
        raise Exception("Unable to initialize connection with Splunk, Splunk client is None")

    # manage kvstore
    indicators_kvstore = "opencti_indicators"
    try:
        # Create KV Store if it doesn't exist
        splunk.kvstore.create(indicators_kvstore)
    except Exception as ex:
        helper.log_info(f"An exception occurred while creating kv_store, {ex}")

    # get proxy setting configuration
    proxy_settings = helper.get_proxy()  #TODO: to take into account

    # get connection configuration
    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")
    disable_ssl_verification = helper.get_global_setting("disable_ssl_verification")
    verif_ssl = True
    if disable_ssl_verification == "1":
        verif_ssl = False
    helper.log_debug(f"Verify SSL: {verif_ssl}")

    stream_id = helper.get_arg('stream_id')
    helper.log_info(f"Going to fetch data of OCTI stream.id: {stream_id}")

    # load kvstore
    kv_store = splunk.kvstore[indicators_kvstore].data

    # get last_id stream
    last_id = helper.get_check_point(input_name) or "0-0"
    helper.log_info(f"last_id: {last_id}")

    # consume OCTI stream
    url = opencti_url+"/stream/"+stream_id
    try:
        messages = SSEClient(
            url,
            last_id,
            headers={
                "authorization": "Bearer "+opencti_api_key,
                "listen-delete": "true",
                "no-dependencies": "true",
                "with-inferences": "true",
            },
            verify=True
        )
    except Exception as ex:
        helper.log_error("An exception occurred while connecting to stream API, check your settings")
        helper.log_error(ex)
        return

    for msg in messages:
        start_time_update_checkpoint = time.time()
        helper.save_check_point(input_name, msg.id)
        helper.log_info("update check point --- %s seconds ---" % (time.time() - start_time_update_checkpoint))
        if msg.event in ["create", "update", "delete"]:
            data = json.loads(msg.data)["data"]
            if data['type'] == "indicator":
                indicator = enrich_payload(helper, data)
                helper.log_info(msg.event +" - "+ msg.id +" - "+indicator['name']+" - "+indicator['pattern'])
                if msg.event == "create" or msg.event == "update":
                    start_time_check_kvstore = time.time()
                    exist = exist_in_kvstore(kv_store, indicator["_key"])
                    helper.log_info("check kvstore --- %s seconds ---" % (time.time() - start_time_check_kvstore))
                    if exist:
                        start_time_update_kvstore = time.time()
                        kv_store.update(indicator["_key"], indicator)
                        helper.log_info("update kvstore --- %s seconds ---" % (time.time() - start_time_update_kvstore))
                    else:
                        indicator['added_at'] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        start_time_insert_kvstore = time.time()
                        kv_store.insert(indicator)
                        helper.log_info("insert kvstore --- %s seconds ---" % (time.time() - start_time_insert_kvstore))
                if msg.event == "delete":
                    exist = exist_in_kvstore(kv_store, indicator["_key"])
                    if exist:
                        start_time_delete_kvstore = time.time()
                        kv_store.delete_by_id(indicator["_key"])
                        helper.log_info("delete kvstore --- %s seconds ---" % (time.time() - start_time_delete_kvstore))

