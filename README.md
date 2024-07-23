# OpenCTI Add On for Splunk

The OpenCTI Add-on for Splunk allows users to interconnect Splunk with OpenCTI platform.

## Key features

- Ability to ingest Indicators exposed through an OpenCTI live stream
- Ability to trigger OpenCTI actions in response of Alerts and to investigate them directly in OpenCTI

## Installation

### Installation from Splunkbase (not ready, waiting for App publication)

1. Log in to the Splunk Web UI and navigate to "Apps" and click on "Find more Apps"
2. Search for OpenCTI
3. Click Install
The app is installed

### Installing from file

1. Download latest version of the Splunk App: TA-opencti-add-on-1.0.0.spl (link)
2. Log in to the Splunk Web UI and navigate to "Apps" and click on "Manage Apps"
3. Click "Install app from file"
4. Choose file and select the "TA-opencti-add-on-1.0.0.spl" file
5. Click on Upload
The app is installed

## Configuration

### OpenCTI user account

Before configuring the App, we strongly recommend that you create a dedicated account in OpenCTI with the same properties as for a connector user account.
To create this account, please refer to the following documentation: https://docs.opencti.io/latest/deployment/connectors/?h=connector+user#connector-users-and-tokens

> [!WARNING]  
> As the application can generate many requests to OpenCTI without maintaining an HTTP session, it's strongly recommended to activate the “Use stateless mode” option on this user account.

Proceed as follows to enable the "stateless mode" option:
1. Update the previously created user and click on "Advanced options"
2. Enable the "Use stateless mode" options

![](./.github/img/config_stateless_mode.png "Stateless Mode")

### General App settings

1. Navigate to Splunk Web UI home page, open the "OpenCTI add-on for Splunk" and navigate to "Configuration" page.
2. Click on "Add-on settings" tab and complete the form with the required settings:

| Parameter         | Description                                  |
|-------------------|----------------------------------------------|
| `OpenCTI URL`     | The URL of the OpenCTI platform              |
| `OpenCTI API Key` | The API Token of the previously created user |
| `Disable SSL`     | Enable or disable SSL verification           |

![](./.github/img/addon_settings.png "Add-on settings")


If a proxy configuration is required to connect to OpenCTI platform, you can configure it on the Proxy page

| Parameter         | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `Enable Proxy`    | Determines whether a proxy is required to communicate with OpenCTI platform |
| `Proxy Host`      | The proxy hostname or IP address                                            |
| `Proxy Port`      | The proxy port                                                              |
| `Proxy Username`  | An optional proxy username                                                  |
| `Proxy Password`  | An optional proxy password                                                  |


### OpenCTI Indicators Inputs Configuration

The “OpenCTI Add-On for Splunk” enables Splunk to be fed with indicators exposed through a live feed. To do this, the add-on implements and manages Splunk modular inputs. Indicators are stored in a dedicated kvstore named “opencti_iocs”. 
A default lookup definition named "opencti_lookup" is also implemented to facilitate indicator management.

Proceed as follows to enable the ingestion of indicators:

1. From the "OpenCTI add-on" sub menus, select the "Inputs" sub menu
2. Click on "Create new input" button to define a new indicators input.
3. Complete the form with the following settings:

| Parameter       | Description                                                                                                    |
|-----------------|----------------------------------------------------------------------------------------------------------------|
| `Name`          | Unique name for the input being configured                                                                     |
| `Interval`      | Time interval of input in seconds. Leave as default (0) to allow continuous execution of the ingestion process. |
| `Index`         | The index that the data will be stored in (default)                                                            |
| `Stream Id`     | The Live Stream ID of the OpenCTI stream to consume                                                            |
| `Import from`   | The number of days to go back for the initial data collection (default: 30) (optional)                                      |

4. Once the Input parameters have been correctly configured click "Add"

![](./.github/img/config_input.png "Indicators Input Configuration")

5. Validate the newly created input and ensure it's set to enabled

As soon as the input is created, the ingestion of indicators begins.
You can monitor the import of these indicators using the following Splunk query that list all indicators ingested in the kvstore: 

```
| inputlookup opencti_lookup
```

You can also consult the "Indicators Dashboard" which gives an overview of the data ingested.


The ingestion process can also be monitored by consulting the log file ```ta_opencti_add_on_opencti_indicators.log``` present in the directory ```$SPLUNK_HOME/var/log/splunk/```





