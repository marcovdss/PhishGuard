import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os

def analyze_html(url):
    """
    Fetches and analyzes the HTML of a given URL to detect suspicious forms or malicious scripts.
    Returns True if suspicious elements are found, otherwise False.
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        # Verify SSL certificates and set reasonable timeout
        response = requests.get(url, headers=headers, timeout=10, verify=True)

        if response.status_code != 200:
            print(f"Error: Unable to fetch page, status code {response.status_code}")
            return False

        soup = BeautifulSoup(response.text, 'html.parser')

        # Get the domain of the original URL for comparison
        original_domain = urlparse(url).netloc.lower()

        # Check for suspicious forms
        for form in soup.find_all("form"):
            action = form.get("action", "").lower()
            if action.startswith("http"):
                action_domain = urlparse(action).netloc.lower()
                if action_domain != original_domain and not action_domain.endswith(f".{original_domain}"):
                    print(f"Suspicious form found! Action: {action}")
                    return True  

            for input_tag in form.find_all("input"):
                input_type = input_tag.get("type", "").lower()
                if input_type == "password" and not any(parent.name == "form" for parent in input_tag.parents):
                    print(f"Password input outside form found: {input_tag}")
                    return True

        # Check for potentially malicious JavaScript
        script_patterns = [
            r"eval\(.+\)",  
            r"document\.write\(.+\)",  
            r"setTimeout\(.+, ?\d+\)",  
            r"unescape\(.+\)",  
            r"atob\(.+\)",
            r"window\.location\s*=\s*['\"]http",
            r"iframe\s*src=['\"]http",
        ]
        
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in script_patterns]
        
        for script in soup.find_all("script"):
            if script.string:
                script_content = script.string
                for pattern in compiled_patterns:
                    if pattern.search(script_content):
                        print(f"Potential malicious script detected: {script_content[:100]}...")
                        return True  

        return False  

    except requests.exceptions.SSLError:
        print("SSL Certificate verification failed")
        return True  # Treat SSL errors as suspicious
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return False  

# Test the function
if __name__ == "__main__":
    # Inside checker/check_html.py
    html_path = os.path.join(os.path.dirname(__file__), "..", "test_phishing.html")
    print(html_path)
    result = analyze_html(html_path) 