import sys
from checker.blacklist import check_blacklist
from checker.blacklist import check_virustotal
from checker.check_ssl import check_ssl
from checker.whois_lookup import get_whois_info

def main():
    if len(sys.argv) < 2:
        print("Uso: python phishguard.py <URL>")
        sys.exit(1)

    url = sys.argv[1]

    print(f"🔍 **Analisando URL**: {url}\n")
    print("="*50)

    try:
        print("🛡️ **Verificação na Google Safe Browsing**:")
        if check_blacklist(url):
            print("🚨 **URL está na blacklist do Google Safe Browsing!**")
        else:
            print("✅ **URL não encontrada na blacklist.**")
    except Exception as e:
        print(f"🚨 **Erro ao verificar no Google Safe Browsing**: {str(e)}")
    print("-"*50)

    
    try:
        print("⚠️ **Verificação no VirusTotal**:")
        virustotal_result = check_virustotal(url)
        
        if isinstance(virustotal_result, dict):
            if virustotal_result.get("malicious", False):
                print(f"🚨 **URL está marcada como maliciosa no VirusTotal.**\nAmeaça: {virustotal_result.get('threat_name', 'Desconhecida')}")
            else:
                print("✅ **URL não está marcada como maliciosa no VirusTotal.**")
        elif isinstance(virustotal_result, bool):
            if virustotal_result:
                print("🚨 **URL está marcada como maliciosa no VirusTotal.**")
            else:
                print("✅ **URL não está marcada como maliciosa no VirusTotal.**")
        else:
            print("🚨 **Erro: O retorno do VirusTotal não é válido.**")
    except Exception as e:
        print(f"🚨 **Erro ao verificar no VirusTotal**: {str(e)}")
    print("-"*50)

    try:
        print("🔒 **Verificação do Certificado SSL**:")
        ssl_result = check_ssl(url)
        if isinstance(ssl_result, bool):
            if ssl_result:
                print("✅ **Certificado SSL está válido.**")
            else:
                print("🚨 **Certificado SSL inválido ou expirado.**")
        else:
            print("🚨 **Erro: O retorno de SSL não é válido.**")
    except Exception as e:
        print(f"🚨 **Erro ao verificar SSL**: {str(e)}")
    print("-"*50)

    print("🔍 **Obtendo informações WHOIS**:\n")
    try:
        whois_info = get_whois_info(url)
        if "error" in whois_info:
            print(f"🚨 **Erro ao obter WHOIS**: {whois_info['error']}")
        else:
            for key, value in whois_info.items():
                print(f"- **{key}**: {value}")
    except Exception as e:
        print(f"🚨 **Erro ao obter informações WHOIS**: {str(e)}")
    
    print("="*50)

if __name__ == "__main__":
    main()
