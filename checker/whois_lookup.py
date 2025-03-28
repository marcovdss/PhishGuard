import whois

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "Domain Name": w.domain_name or "N/A",
            "Registrar": w.registrar or "N/A",
            "Creation Date": w.creation_date or "N/A",
            "Expiration Date": w.expiration_date or "N/A",
            "Name Servers": ", ".join(w.name_servers) if w.name_servers else "N/A"
        }
    except Exception as e:
        return {
            "error": f"Erro ao obter WHOIS: {str(e)}"
        }

#print (check_ssl("https://www.google.com"))