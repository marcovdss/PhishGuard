import sys
from checker.blacklist import check_blacklist

def main():
    if len(sys.argv) < 2:
        print("Uso: python phishguard.py <URL>")
        sys.exit(1)

    url = sys.argv[1]

    print(f"🔍 Analisando: {url}\n")

    # Verificar blacklist
    if check_blacklist(url):
        print("🚨 URL está na blacklist do Google Safe Browsing!")
    else:
        print("✅ URL não encontrada na blacklist.")

if __name__ == "__main__":
    main()