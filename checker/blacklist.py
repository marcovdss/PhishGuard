import requests
from config import GOOGLE_SAFE_BROWSING_API_KEY

def check_blacklist(url):
    """Verifica se a URL está na blacklist do Google Safe Browsing."""
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GOOGLE_SAFE_BROWSING_API_KEY
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    return response.json().get("matches") is not None
