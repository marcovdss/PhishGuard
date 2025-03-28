import requests
import os
from dotenv import load_dotenv

# Carregar variáveis do .env
load_dotenv()

def check_blacklist(url):
    """Verifica se a URL está na blacklist do Google Safe Browsing."""
    # Obter a chave da API do arquivo .env
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

    if not api_key:
        raise ValueError("A chave da API do Google Safe Browsing não foi encontrada no arquivo .env.")

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
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
    
    # Retornar se a URL está ou não na blacklist
    return response.json().get("matches") is not None
