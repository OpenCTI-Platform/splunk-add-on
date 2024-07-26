import requests

from utils import get_proxy_config
from constants import VERIFY_SSL

class SplunkAppConnectorHelper:
    def __init__(
            self,
            connector_id,
            connector_name,
            opencti_url,
            opencti_api_key,
            splunk_helper
    ):
        self.connector_id = connector_id
        self.connector_name = connector_name
        self.opencti_url = opencti_url
        self.splunk_helper = splunk_helper
        self.headers = {
            "Authorization": "Bearer " + opencti_api_key,
        }
        self.api_url = self.opencti_url + "/graphql"

        # manage SSL verification
        splunk_helper.log_debug(f"verify SSL: {VERIFY_SSL}")

        # manage proxies configuration
        self.proxies = get_proxy_config(splunk_helper)

    def register(self):
        """
        :return:
        """
        input = {
            "input": {
                "id": self.connector_id,
                "name": self.connector_name,
                "type": "STREAM",
                "scope": "",
                "auto": False,
                "only_contextual": False,
                "playbook_compatible": False,
            }
        }

        query = """
            mutation RegisterConnector($input: RegisterConnectorInput) {
                registerConnector(input: $input) {
                    id
                    connector_state
                    config {
                        connection {
                            host
                            vhost
                            use_ssl
                            port
                            user
                            pass
                        }
                        listen
                        listen_routing
                        listen_exchange
                        push
                        push_routing
                        push_exchange
                    }
                    connector_user_id
                }
            }
        """

        r = requests.post(
            url=self.api_url,
            json={"query": query, "variables": input},
            headers=self.headers,
            verify=VERIFY_SSL,
            proxies=self.proxies
        )

        if r.status_code != 200:
            raise Exception(f"An exception occurred while registering Splunk App, "
                            f"received status code: {r.status_code}, exception: {r.content}")

    def send_stix_bundle(self, bundle):
        """
        :param bundle:
        :return:
        """
        query = """
            mutation stixBundle($id: String!, $bundle: String!) {
                stixBundlePush(connectorId: $id, bundle: $bundle)
            }
        """

        variables = {
            "id": self.connector_id,
            "bundle": bundle
        }

        r = requests.post(
            url=self.api_url,
            json={"query": query, "variables": variables},
            headers=self.headers,
            verify=VERIFY_SSL,
            proxies=self.proxies
        )
        if r.status_code != 200:
            raise Exception(f"An exception occurred while sending STIX bundle, "
                            f"received status code: {r.status_code}, exception: {r.content}")
