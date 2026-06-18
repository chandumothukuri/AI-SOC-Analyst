def get_asset_criticality(host):

    assets = {

        "DC01": "Critical",

        "FILESERVER01": "High",

        "WEB01": "High",

        "HR-PC": "Medium",

        "WIN10-PC": "Low"
    }

    return assets.get(host, "Unknown")