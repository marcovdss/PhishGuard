import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

def check_ssl(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    if ":" in hostname:
        hostname = hostname.split(":")[0]
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        
        not_before = cert['notBefore']
        not_after = cert['notAfter']
        
        not_before_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y GMT")
        not_after_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
        
        not_before_date = not_before_date.replace(tzinfo=timezone.utc)
        not_after_date = not_after_date.replace(tzinfo=timezone.utc)  
        
        validity_days = (not_after_date - not_before_date).days
        days_remaining = (not_after_date - datetime.now(timezone.utc)).days
        
        print(f"Validade do certificado: {validity_days} dias")
        return days_remaining > 0
    
    except Exception as e:
        print(f"Erro ao verificar SSL: {e}")
        return False
