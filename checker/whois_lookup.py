import whois
from datetime import datetime

def get_whois_info(domain):
    try:
        w = whois.whois(domain)

        def get_first_value(value):
            if isinstance(value, list):
                return value[0]
            return value

        def format_datetime(value):
            if isinstance(value, datetime):
                return value.strftime("%Y-%m-%d %H:%M:%S")
            return value

        return {
            "Domain Name": get_first_value(w.domain_name) or "N/A",
            "Registrar": get_first_value(w.registrar) or "N/A",
            "Creation Date": format_datetime(get_first_value(w.creation_date)) or "N/A",
            "Expiration Date": format_datetime(get_first_value(w.expiration_date)) or "N/A",
            "Name Servers": ", ".join(w.name_servers) if w.name_servers else "N/A"
        }
    except Exception as e:
        return {
            "error": f"Erro ao obter WHOIS: {str(e)}"
        }
