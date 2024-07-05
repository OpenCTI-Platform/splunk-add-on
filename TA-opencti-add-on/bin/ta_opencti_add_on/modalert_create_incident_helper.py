# encoding = utf-8
import json
from datetime import datetime
from utils import get_marking_id, extract_observables_from_cim_model
from common import process_labels, init_octi_client

def create_incident(helper, event):

    if helper.get_param("labels") == '':
        labels = []
    else:
        labels = [x.strip() for x in helper.get_param("labels").split(',')]
    # remove potential empty labels
    labels = list(filter(None, labels))

    alert_params = {
        "name": helper.get_param("name"),
        "description": helper.get_param("description"),
        "type": helper.get_param("type"),
        "severity": helper.get_param("severity"),
        "labels": labels,
        "tlp": helper.get_param("tlp"),
        "date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    helper.log_debug("Alert params={}".format(alert_params))

    try:
        # OpenCTI client initialization
        opencti_api_client = init_octi_client(helper)

        # process labels creation
        process_labels(opencti_api_client, alert_params.get("labels"))

        # create the identity
        identity = opencti_api_client.identity.create(
            type="System",
            name=event.get("host")
        )

        # create the incident
        incident = opencti_api_client.incident.create(
            name=alert_params.get("name"),
            description=event.get("_raw"),
            severity=alert_params.get("severity"),
            incident_type=alert_params.get("type"),
            tlp=alert_params.get("tlp"),
            first_seen=alert_params.get("date"),
            created=alert_params.get("date"),
            objectLabel=alert_params.get("labels"),
            objectMarking=[get_marking_id(alert_params.get("tlp"))["id"]],
            createdBy=identity["id"]
        )

        # extract observables from _raw alert
        observables = extract_observables_from_cim_model(event)
        observable_refs = []

        # create extracted observables
        for observable in observables:
            if observable["type"] == "url":
                octi_observable = opencti_api_client.stix_cyber_observable.create(
                    simple_observable_key="Url.value",
                    simple_observable_value=observable["value"]
                )
                observable_refs.append(octi_observable["id"])
            elif observable["type"] == "ipv4":
                octi_observable = opencti_api_client.stix_cyber_observable.create(
                    simple_observable_key="IPv4-Addr.value",
                    simple_observable_value=observable["value"]
                )
                observable_refs.append(octi_observable["id"])
            elif observable["type"] == "ipv6":
                octi_observable = opencti_api_client.stix_cyber_observable.create(
                    simple_observable_key="IPv6-Addr.value",
                    simple_observable_value=observable["value"]
                )
                observable_refs.append(octi_observable["id"])
            elif observable["type"] == "domain":
                octi_observable = opencti_api_client.stix_cyber_observable.create(
                    simple_observable_key="Domain-Name.value",
                    simple_observable_value=observable["value"]
                )
                observable_refs.append(octi_observable["id"])
            elif observable["type"] == "user-agent":
                octi_observable = opencti_api_client.stix_cyber_observable.create(
                    simple_observable_key="User-Agent.value",
                    simple_observable_value=observable["value"]
                )
                observable_refs.append(octi_observable["id"])
            else:
                helper.log_error("Unable to map observable: {}", observable["type"])

        # link observables to incident
        for observable_ref in observable_refs:
            opencti_api_client.stix_core_relationship.create(
                fromId=observable_ref,
                toId=incident["id"],
                relationship_type="related-to",
                start_time=alert_params.get("date"),
                stop_time=alert_params.get("date"),
                objectMarking=[get_marking_id(alert_params.get("tlp"))["id"]],
                created_by=identity["id"]
            )
        helper.log_info("Incident successfully created")
    except Exception as ex:
        helper.log_info(ex)

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

    # helper.log_info("args={}".format(args))
    # helper.log_info("kwargs={}".format(kwargs))

    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(json.dumps(event)))
        create_incident(helper, event)

    return 0

