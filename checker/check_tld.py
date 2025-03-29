from tld import get_tld, is_tld

def check_tld(url):
    """
    Obtém informações detalhadas sobre o domínio da URL fornecida.
    """ 
    try:
        # Ensure URL has a scheme (http:// or https://)
        if not url.startswith(("http://", "https://")):
            url = "https://" + url  # Default to https
        
        domain_info = get_tld(url, as_object=True)
        
        domain_details = {
            "domain": domain_info.domain,
            "suffix": domain_info.suffix,
            "subdomain": domain_info.subdomain,
            "tld": domain_info.tld
        }

        tld_str = f"{domain_info.tld}"

        return is_tld(tld_str)
    
    except Exception as e:
        return False
