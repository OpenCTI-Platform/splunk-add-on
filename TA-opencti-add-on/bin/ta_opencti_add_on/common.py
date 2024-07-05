from pycti import OpenCTIApiClient

def process_labels(opencti_api_client, values):
    color = "#00a8cc"
    for value in values:
        opencti_api_client.label.create(
            value=value, color=color, update=False
        )

def init_octi_client(helper):

    # load opencti global configuration
    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")

    # manage proxy settings
    proxy_uri = helper._get_proxy_uri()
    proxies = {
        "http": proxy_uri,
        "https": proxy_uri
    }
    helper.log_debug(f"Proxy: {proxies}")

    # manage ssl verification
    disable_ssl_verification = helper.get_global_setting("disable_ssl_verification")
    verif_ssl = True
    if disable_ssl_verification == "1":
        verif_ssl = False
    helper.log_debug(f"verify SSL: {verif_ssl}")

    # OpenCTI client initialization
    opencti_api_client = OpenCTIApiClient(
        url=opencti_url,
        token=opencti_api_key,
        ssl_verify=verif_ssl,
        proxies=proxies
    )

    return opencti_api_client