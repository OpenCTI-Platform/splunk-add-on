

[opencti_create_incident]
python.version = python3
param.name = <string> Name. It's a required parameter. It's default value is $name$.
param.description = <string> Description.  It's default value is $description$.
param.type = <string> Type.
param.severity = <list> Severity. It's default value is medium.
param.labels = <string> Labels.
param.tlp = <list> TLP.  It's default value is tlp_amber.
param.observables_extraction = <list> Observables extraction. It's default value is disable.

[opencti_create_incident_response]
python.version = python3
param.name = <string> Name. It's a required parameter. It's default value is $name$.
param.description = <string> Description.  It's default value is $description$.
param.severity = <list> Severity.  It's default value is medium.
param.priority = <list> Priority.  It's default value is p2.
param.type = <string> Type.
param.case_template = <string> Case Template.
param.labels = <string> Labels.
param.tlp = <list> TLP.  It's default value is tlp_amber.
param.observables_extraction = <list> Observables extraction. It's default value is disable.

[opencti_create_sighting]
python.version = python3
param.sighting_of_value = <string> Sighting Of (value). It's a required parameter.
param.sighting_of_type = <string> Sighting Of (type). It's a required parameter.
param.where_sighted_value = <string> Where Sighted (value). It's default value is Splunk.
param.where_sighted_type = <string> Where Sighted (type). It's default value is System.
param.labels = <string> Labels.
param.tlp = <list> TLP.  It's default value is tlp_amber.
