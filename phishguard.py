import sys
import json
from checker.blacklist import check_blacklist
from checker.blacklist import check_virustotal
from checker.check_ssl import check_ssl
from checker.whois_lookup import get_whois_info
from checker.check_tld import check_tld

def main():
    if len(sys.argv) < 2:
        print("Uso: python phishguard.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    report = {"url": url, "results": {}}
    
    print(f"🔍 **Analisando URL**: {url}\n")
    print("="*50)

    try:
        print("🛡️ **Verificação na Google Safe Browsing**:")
        result = check_blacklist(url)
        message = "🚨 URL está na blacklist do Google Safe Browsing!" if result else "✅ URL não encontrada na blacklist."
        print(message)
        report["results"]["blacklist"] = message
    except Exception as e:
        error_message = f"🚨 Erro ao verificar no Google Safe Browsing: {str(e)}"
        print(error_message)
        report["results"]["blacklist"] = error_message
    print("-"*50)
    
    try:
        print("⚠️ **Verificação no VirusTotal**:")
        virustotal_result = check_virustotal(url)
        if isinstance(virustotal_result, dict):
            if virustotal_result.get("malicious", False):
                message = f"🚨 URL está marcada como maliciosa no VirusTotal. Ameaça: {virustotal_result.get('threat_name', 'Desconhecida')}"
            else:
                message = "✅ URL não está marcada como maliciosa no VirusTotal."
        elif isinstance(virustotal_result, bool):
            message = "🚨 URL está marcada como maliciosa no VirusTotal." if virustotal_result else "✅ URL não está marcada como maliciosa no VirusTotal."
        else:
            message = "🚨 Erro: O retorno do VirusTotal não é válido."
        print(message)
        report["results"]["virustotal"] = message
    except Exception as e:
        error_message = f"🚨 Erro ao verificar no VirusTotal: {str(e)}"
        print(error_message)
        report["results"]["virustotal"] = error_message
    print("-"*50)
    
    try:
        print("🔒 **Verificação do Certificado SSL**:")
        ssl_result = check_ssl(url)
        message = "✅ Certificado SSL está válido." if ssl_result else "🚨 Certificado SSL inválido ou expirado."
        print(message)
        report["results"]["ssl"] = message
    except Exception as e:
        error_message = f"🚨 Erro ao verificar SSL: {str(e)}"
        print(error_message)
        report["results"]["ssl"] = error_message
    print("-"*50)
    
    print("🔍 **Obtendo informações WHOIS**:\n")
    try:
        whois_info = get_whois_info(url)
        if "error" in whois_info:
            message = f"🚨 Erro ao obter WHOIS: {whois_info['error']}"
            print(message)
            report["results"]["whois"] = message
        else:
            whois_data = {key: value for key, value in whois_info.items()}
            for key, value in whois_data.items():
                print(f"- {key}: {value}")
            report["results"]["whois"] = whois_data
    except Exception as e:
        error_message = f"🚨 Erro ao obter informações WHOIS: {str(e)}"
        print(error_message)
        report["results"]["whois"] = error_message
    print("="*50)
    
    try:
        print("🔍 **Verificação do TLD**:")
        result = check_tld(url)
        message = "✅ TLD é válido." if result else "🚨 TLD inválido."
        print(message)
        report["results"]["tld"] = message
    except Exception as e:
        error_message = f"🚨 Erro ao verificar TLD: {str(e)}"
        print(error_message)
        report["results"]["tld"] = error_message
    
    with open("report.json", "w", encoding="utf-8") as json_file:
        json.dump(report, json_file, ensure_ascii=False, indent=4)
    
    print("📄 Relatório salvo em report.json")
    
if __name__ == "__main__":
    main()
