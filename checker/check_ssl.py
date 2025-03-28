import ssl
import socket
from urllib.parse import urlparse

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
        expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
        days_remaining = (expiry_date - ssl.cert_time_to_seconds(cert['notBefore'])) / (60 * 60 * 24)
        return days_remaining > 0
    except Exception as e:
        return False

print(check_ssl("https://example.com"))

