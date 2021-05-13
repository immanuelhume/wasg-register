# ISP URLs were taken from WSG.Common.dll
# Test URL is for debugging.
ISP_CONFIG = {
    "singtel": {
        "essa_url": "https://singtel-wsg.singtel.com/essa_r11",
        "create_api_versions": ("2.4", "2.4"),
        "retrieve_api_versions": ("1.7", "2.2"),
    },
    "myrepublic": {
        "essa_url": "https://wireless-sg-app.myrepublic.net/essa_r11",
        "create_api_versions": ("2.3", "2.4"),
        "retrieve_api_versions": ("1.6", "2.2"),
    },
}

DEFAULT_ISP = "singtel"

# The transaction ID (transid) appears to be created from the WiFi
# interface's GUID in Windows, which is probably based on the MAC
# address. The below transid was found within WSG.Common.dll, and is used
# when there is no "DeviceManager" available. It seems to work fine.
DEFAULT_TRANSID = b"053786654500000000000000"


# Result Codes
RC_SUCCESS = 1100
