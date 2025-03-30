import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()

def check_blacklist(url):
    """Verifica se a URL está na blacklist do Google Safe Browsing."""
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
    
    return response.json().get("matches") is not None

def check_virustotal(url):
    """Verifica se a URL está no banco de dados do VirusTotal."""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')

    if not api_key:
        raise ValueError("A chave da API do VirusTotal não foi encontrada no arquivo .env.")
    
    url_encoded = base64.urlsafe_b64encode(url.encode('utf-8')).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_encoded}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if "data" in data and "attributes" in data["data"]:
                attributes = data["data"]["attributes"]
                return attributes["last_analysis_stats"]["malicious"] > 0
        
        print(f"Erro ao fazer a requisição para o VirusTotal. Status code: {response.status_code}")
        return None  # Indica que não foi possível verificar

    except requests.RequestException as e:
        print(f"Erro de conexão com VirusTotal: {e}")
        return None  # Indica erro na requisição