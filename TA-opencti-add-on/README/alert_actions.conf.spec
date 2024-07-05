

[create_sighting]
python.version = python3
param.labels = <string> Labels.
param.tlp = <list> TLP.  It's default value is tlp_amber.

[create_incident]
python.version = python3
param.name = <string> Name. It's a required parameter. It's default value is $name$.
param.description = <string> Description.  It's default value is $description$.
param.type = <string> Type.
param.severity = <list> Severity. It's default value is medium.
param.labels = <string> Labels.
param.tlp = <list> TLP.  It's default value is tlp_amber.

[create_incident_response]
python.version = python3
param.name = <string> Name. It's a required parameter. It's default value is $name$.
param.description = <string> Description.  It's default value is $description$.
param.severity = <list> Severity.  It's default value is medium.
param.priority = <list> Priority.  It's default value is p2.
param.type = <string> Type.
param.case_template = <string> Case Template.
param.labels = <string> Labels.
param.tlp = <list> TLP.  It's default value is tlp_amber.

