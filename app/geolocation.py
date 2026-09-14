"""
Geolocation lookup for an IP address, using the free ip-api.com service.
No API key needed. Rate limit: 45 requests/minute, which is fine for our use.

Extended for Feature 3 (Origin Traceability) to also request:
  - proxy: is this a known VPN/proxy/Tor exit node?
  - hosting: does this IP belong to a hosting/data-center provider
    (i.e. NOT a residential/business ISP — a strong signal for spoofed
    or bot-driven infrastructure)?
  - mobile: is this a mobile/cellular connection?
"""

import requests

FIELDS = "status,message,country,regionName,city,isp,org,lat,lon,proxy,hosting,mobile,query"


def geolocate_ip(ip_address):
    """
    Look up an IP address and return location + infrastructure info as a dict.
    Returns None if given no IP, or a dict with an "error" key if the lookup fails.
    """
    if ip_address is None:
        return None

    url = f"http://ip-api.com/json/{ip_address}?fields={FIELDS}"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}"}

    if data.get("status") == "fail":
        return {"error": data.get("message", "Unknown lookup failure")}

    return {
        "ip": ip_address,
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "is_proxy_or_vpn": data.get("proxy", False),
        "is_hosting_provider": data.get("hosting", False),
        "is_mobile": data.get("mobile", False),
    }


if __name__ == "__main__":
    import json
    result = geolocate_ip("103.216.92.10")
    print(json.dumps(result, indent=2))

    result2 = geolocate_ip("8.8.8.8")
    print(json.dumps(result2, indent=2))