# encoding = utf-8
import json
from app_connector_helper import SplunkAppConnectorHelper
from stix_converter import convert_to_sighting
from constants import CONNECTOR_NAME, CONNECTOR_ID


def create_sighting(helper, event):
    """
    :param helper:
    :param event:
    :return:
    """
    if helper.get_param("labels"):
        labels = [x.strip() for x in helper.get_param("labels").split(',')]
    else:
        labels = []
    # remove potential empty labels
    labels = list(filter(None, labels))

    helper.log_info(helper.get_param("sighting_of_value"))
    helper.log_info(type(helper.get_param("sighting_of_value")))
    helper.log_info(helper.get_param("sighting_of_type"))
    helper.log_info(type(helper.get_param("sighting_of_type")))
    helper.log_info(helper.get_param("where_sighted_value"))
    helper.log_info(type(helper.get_param("where_sighted_value")))
    helper.log_info(helper.get_param("where_sighted_type"))
    helper.log_info(type(helper.get_param("where_sighted_type")))
    helper.log_info(labels)
    helper.log_info(helper.get_param("tlp"))

    params = {
        "sighting_of_value": helper.get_param("sighting_of_value"),
        "sighting_of_type": helper.get_param("sighting_of_type"),
        "where_sighted_value": helper.get_param("where_sighted_value"),
        "where_sighted_type": helper.get_param("where_sighted_type"),
        "labels": labels,
        "tlp": helper.get_param("tlp"),
    }

    helper.log_info(f"Alert params={params}")

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
    bundle = convert_to_sighting(
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
    labels = helper.get_param("labels")
    helper.log_info("labels={}".format(labels))

    tlp = helper.get_param("tlp")
    helper.log_info("tlp={}".format(tlp))

    observables_extraction = helper.get_param("observables_extraction")
    helper.log_info("observables_extraction={}".format(observables_extraction))


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

    helper.log_info("Alert action create_sighting started.")

    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(json.dumps(event)))
        create_sighting(helper, event)

    return 0
