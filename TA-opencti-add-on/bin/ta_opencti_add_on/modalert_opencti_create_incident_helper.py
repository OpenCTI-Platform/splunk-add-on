# encoding = utf-8
import json
from datetime import datetime

from app_connector_helper import SplunkAppConnectorHelper
from constants import CONNECTOR_ID, CONNECTOR_NAME
from stix_converter import convert_to_incident


def create_incident(helper, event):
    if helper.get_param("labels") == '':
        labels = []
    else:
        labels = [x.strip() for x in helper.get_param("labels").split(',')]
    # remove potential empty labels
    labels = list(filter(None, labels))

    helper.log_info(helper.get_param("observables_extraction"))

    params = {
        "name": helper.get_param("name"),
        "description": helper.get_param("description"),
        "type": helper.get_param("type"),
        "severity": helper.get_param("severity"),
        "labels": labels,
        "tlp": helper.get_param("tlp"),
        "date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observables_extraction": helper.get_param("observables_extraction")
    }
    helper.log_debug(f"Alert params={params}")

    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")

    splunk_app_connector = SplunkAppConnectorHelper(
        connector_id=CONNECTOR_ID,
        connector_name=CONNECTOR_NAME,
        opencti_url=opencti_url,
        opencti_api_key=opencti_api_key,
        splunk_helper=helper
    )

    # convert to_stix
    bundle = convert_to_incident(
        alert_params=params,
        event=event
    )

    # going to register App as an OpenCTI connector
    # TODO: Do this only on time (at first run)
    try:
        splunk_app_connector.register()
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
                         f"an exception occurred while registering App as OpenCTI connector, "
                         f"exception: {str(ex)}")
        return

    try:
        splunk_app_connector.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
                         f"an exception occurred while sending STIX bundle,"
                         f"exception: {str(ex)}")
        return


def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the alert action parameters and prints them to the log
    name = helper.get_param("name")
    helper.log_info("name={}".format(name))

    description = helper.get_param("description")
    helper.log_info("description={}".format(description))

    type = helper.get_param("type")
    helper.log_info("type={}".format(type))

    severity = helper.get_param("severity")
    helper.log_info("severity={}".format(severity))

    labels = helper.get_param("labels")
    helper.log_info("labels={}".format(labels))

    tlp = helper.get_param("tlp")
    helper.log_info("tlp={}".format(tlp))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    # Set the current LOG level
    helper.set_log_level(helper.log_level)

    helper.log_info("Alert action create_incident started.")

    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(json.dumps(event)))
        create_incident(helper, event)

    return 0
