#  PhishGuard - Detector de Phishing

PhishGuard é uma ferramenta de segurança cibernética para analisar URLs suspeitas e detectar possíveis sites de phishing. Ele verifica listas negras, analisa certificados SSL, obtém informações WHOIS e inspeciona o conteúdo HTML em busca de elementos maliciosos.

##  Funcionalidades

 - **Verificação de blacklist:** Confere a URL em bancos de dados de phishing (Google Safe Browsing, OpenPhish, PhishTank).  
 - **Análise de SSL:** Verifica a validade e confiabilidade do certificado SSL do site.  
 - **WHOIS Lookup:** Obtém informações sobre o domínio (registrante, país, datas de criação/expiração).  
 - **Verificação de similaridade de domínio:** Identifica domínios que tentam imitar sites legítimos.  
 - **Análise de HTML e links:** Detecta formulários suspeitos e scripts maliciosos.  
 - **Relatório em JSON:** Gera um resumo estruturado dos resultados.  

---

##  Tecnologias Utilizadas

- **Python 3**
- **Requests** (para requisições HTTP)
- **BeautifulSoup** (para análise de HTML)
- **Whois** (para informações de domínio)
- **tldextract** (para validação de domínios)
- **Google Safe Browsing API** (para checagem de phishing)
- **VirusTotal API (opcional)** (para análise avançada)

---

##  Instalação e Configuração

1. Clone o repositório:
   ```sh
   git clone https://github.com/seu-usuario/PhishGuard.git
   cd PhishGuard
   ```
2. Crie um ambiente virtual e instale as dependências:
   ```sh
   python3 -m venv venv
   source venv/bin/activate  # No Windows use: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Configure as chaves de API (opcional):
   - Crie um arquivo `.env` na raiz do projeto e adicione:
     ```sh
     GOOGLE_SAFE_BROWSING_API_KEY=SUACHAVEAQUI
     VIRUSTOTAL_API_KEY=SUACHAVEAQUI
     ```

---

##  Como Usar

Execute o PhishGuard passando a URL suspeita como argumento:
```sh
python phishguard.py https://site-suspeito.com
```

Exemplo de saída:
```json
{
  "url": "https://site-suspeito.com",
  "blacklist": "Presente no Google Safe Browsing",
  "ssl_valid": false,
  "whois": {
    "registrar": "Namecheap",
    "creation_date": "2024-01-01"
  },
  "html_analysis": "Formulários suspeitos detectados"
}
```

---

##  Licença

Este projeto é licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
