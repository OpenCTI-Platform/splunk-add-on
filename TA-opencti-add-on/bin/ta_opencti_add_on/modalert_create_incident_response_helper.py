# encoding = utf-8
import json
from pycti import OpenCTIApiClient
from datetime import datetime
from utils import get_marking_id, extract_observables_from_cim_model

def create_incident_response(helper, event):

    alert_params = {
        "name": helper.get_param("name"),
        "description": helper.get_param("description"),
        "type": helper.get_param("type"),
        "severity": helper.get_param("severity"),
        "priority": helper.get_param("priority"),
        "labels": helper.get_param("labels"),
        "tlp": helper.get_param("tlp"),
        "date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    helper.log_info("Alert params={}".format(alert_params))

    try:
        # load opencti global configuration
        opencti_url = helper.get_global_setting("opencti_url")
        opencti_api_key = helper.get_global_setting("opencti_api_key")

        # OpenCTI initialization
        opencti_api_client = OpenCTIApiClient(opencti_url, opencti_api_key)

        # Create the identity
        identity = opencti_api_client.identity.create(
            type="System",
            name=event.get("host")
        )

        # Create the incident response case
        incident = opencti_api_client.case_incident.create(
            name=alert_params.get("name"),
            description=event.get("_raw"),
            severity=alert_params.get("severity"),
            priority=alert_params.get("priority"),
            response_types=alert_params.get("type"),
            tlp=alert_params.get("tlp"),
            first_seen=alert_params.get("date"),
            created=alert_params.get("date"),
            objectLabel=alert_params.get("labels"),
            objectMarking=[get_marking_id(alert_params.get("tlp"))["id"]],
            createdBy=identity["id"]
        )

        # Extract observables from _raw alert
        observables = extract_observables_from_cim_model(event)
        observable_refs = []

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

        for observable_ref in observable_refs:
            opencti_api_client.case_incident.add_stix_object_or_stix_relationship(
                id=incident["id"],
                stixObjectOrStixRelationshipId=observable_ref
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

    severity = helper.get_param("severity")
    helper.log_info("severity={}".format(severity))

    priority = helper.get_param("priority")
    helper.log_info("priority={}".format(priority))

    type = helper.get_param("type")
    helper.log_info("type={}".format(type))

    case_template = helper.get_param("case_template")
    helper.log_info("case_template={}".format(case_template))

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
    helper.log_info(helper.log_level)
    helper.set_log_level(helper.log_level)

    helper.log_info("Alert action create_incident_response started.")

    helper.log_info("args={}".format(args))
    helper.log_info("kwargs={}".format(kwargs))

    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(json.dumps(event)))
        create_incident_response(helper, event)

    return 0
