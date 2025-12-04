from datetime import datetime
import subprocess
from ollama import Client
import requests
import dotenv
import sys
import os
import hashlib

def run_ip_analysis():
    client=Client()
    files=[]

    ip = input("Digite o endereço IP a ser analisado (ex: 192.168.0.1): ").strip()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': 'https://urlscan.io/',
        'DNT': '1',
    }

    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    dotenv.load_dotenv(dotenv_path=dotenv_path)

    VT_API_KEY = os.getenv("VT_API_KEY")
    ALIEN_VAULT_API_KEY = os.getenv("ALIEN_VAULT_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    
    print(f"Coletando informações para o IP: {ip}...")

    sanitized_ip = ip.replace('.', '_')
    report_filename = f"threat_report_{sanitized_ip}.md"
    json_filename = f"threat_data_{sanitized_ip}.txt"

    def get_cli_whois(ip):
        process = subprocess.Popen(
            ['whois', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )   

        output_lines = []

        for line in process.stdout:
            output_lines.append(line)
        
        stdout = ''.join(output_lines)
        stderr = process.stderr.read()
        return_code = process.wait()
        if return_code != 0 and not stdout:
            return f"Erro ao obter dados do WHOIS: {stderr}"
        else:
            return stdout.replace('"""', '\\"\\"\\"')
    
    def get_cli_header(ip):
        process = subprocess.Popen(
            ['curl', '-v', '-I', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )   

        output_lines = []

        for line in process.stdout:
            output_lines.append(line)
        
        stdout = ''.join(output_lines)
        stderr = process.stderr.read()
        return_code = process.wait()
        if return_code != 0 and not stdout:
            return f"Erro ao obter dados de cabeçalho pelo cURL: {stderr}"
        else:
            return stdout.replace('"""', '\\"\\"\\"')


    def seach_urlscan(ip):
        url_scan_reponse = requests.get(f'https://urlscan.io/api/v1/search/?q=ip:{ip}')
        url_scan_reponse.raise_for_status()

        url_scan_data=url_scan_reponse.json()
        if url_scan_data.get('results'): # Limita os resultados para evitar prompts muito longos
            results = url_scan_data.get("results", [])
            
            # Extrai apenas informações essenciais de cada resultado
            summarized_results = []
            for result in results[:20]: 
                summary = {
                    "task": result.get("task"),
                    "page": {"domain": result.get("page", {}).get("domain"), "ip": result.get("page", {}).get("ip")},
                    "stats": result.get("stats"),
                }
                summarized_results.append(summary)

            url_scan_final = str({"results": summarized_results})
            return url_scan_final
        return url_scan_reponse.text


    try:

        shodan_host_info = requests.get(f'https://www.shodan.io/host/{ip}', headers=headers)
        shodan_host_info.raise_for_status()  # Verifica se a requisição foi bem-sucedida
        shodan_text = shodan_host_info.text.replace('"""', '\\"\\"\\"') # Escapa aspas triplas

        ipinfo_response = requests.get(f'https://ipinfo.io/{ip}/json', headers=headers)
        ipinfo_response.raise_for_status() 

        url_scan_reponse = seach_urlscan(ip)

        vt_details_response = requests.get(f'https://www.virustotal.com/api/v3/search?query={ip}', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_details_response.raise_for_status()

        whois_text = get_cli_whois(ip)

        headers_text = get_cli_header(ip)
        
        ipdb_response = requests.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}', headers={
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        },
        params={
            'ipAddress': ip,
            'maxAgeInDays': 90
        })
        ipdb_response.raise_for_status()

        av_response = requests.get(f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general', headers={
            'accept': 'application/json',
            'X-OTX-API-KEY': ALIEN_VAULT_API_KEY
        })
        av_response.raise_for_status()
        
        av_data = av_response.json()
        # Limita os dados do Alien Vault para incluir apenas os pulsos (relatórios de ameaças)
        if 'pulse_info' in av_data and 'pulses' in av_data['pulse_info']:
            av_details_text = str({"pulses": av_data['pulse_info']['pulses']})
        else:
            av_details_text = av_response.text

        # Combinar todos os dados em uma única string para a IA
        combined_content = f"""
        ## DADOS COLETADOS PARA ANÁLISE DE THREAT INTELLIGENCE

        TIMESTAMP: {datetime.now().isoformat()}

        ### 1. Informações do Shodan
        ```html
        {shodan_text}
        ```

        ### 2. Informações do IPInfo.io
        ```json
        {ipinfo_response.text}
        ```

        ### 3. Resultados do URLScan.io
        ```json
        {url_scan_reponse}
        ```

        ### 4. Informações do VirusTotal
        ```json
        {vt_details_response}
       ```

        ### 5. Informações do AbuseIPDB
        ```json 
        {ipdb_response.text}
        ```

        ### 6. Informações do WHOIS via comando
        ```html
        {whois_text}
        ```

        ### 7. Informações do Alien Vault OTX
        ```json
        {av_details_text}
        ```

        ### 8. Cabeçalhos HTTP via cURL
        ```html
        {headers_text}
        ```
        """
        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = f"""
    Você é um especialista em Threat Intelligence. Analise os dados brutos fornecidos (em formato JSON e texto) sobre um endereço IP e gere um relatório de inteligência de ameaças.

    **Seu relatório deve conter:**
    1.  **Resumo Executivo:** Um parágrafo conciso com as principais descobertas (localização, ISP, comportamento suspeito, portas críticas).
    2.  **Análise de Comportamento:** Avalie se há indícios de atividade maliciosa, como associação com botnets, scanners, ou servidores de C2, com base nos dados do Shodan e outras fontes.
    3.  **Superfície de Ataque:**
        - Liste todas as **portas abertas** e os **serviços** correspondentes.
        - Liste **vulnerabilidades (CVEs)** identificadas pelo Shodan, se houver, de forma breve, apontando sua relação com possíveis comportamentos maliciosos do IP analisado, assumindo que ele possa ser vetor de ataque.
    4.  **Informações de Rede e Geográficas:**
        - **ASN:** Número e nome da organização.
        - **Provedor (ISP):** Nome do provedor.
        - **Localização:** Cidade, Região, País.
    5.  **Recomendações:** Sugira os próximos passos para uma investigação mais aprofundada (ex: verificar logs de firewall, procurar o IP em feeds de ameaças, etc.).
    6. Seu foco é identificar potenciais riscos e comportamentos maliciosos associados ao IP analisado.

    **Não fornecer orientação de mitigações de vulnerabilidades apontadas pelo Shodan. Seu papel é identificar comportamentos e riscos associados ao IP analisado para proteção de outros usuários, não fornecer orientação de proteção para o sistema dele.**
    **Formato:** Use Markdown e responda em **português do Brasil**.

    **Sempre Iniciar o relatório com o seguinte formato de cabeçalho**
    # Relatório de Threat Intelligence – IP **(Número do IP Analisado)**

    > **Fonte dos dados**: (Fontes utilizadas, ex: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io).  
    > **Timestamp da Análise**: {datetime.now().isoformat()}.  
    """.strip()

    message = [
        {
            'role': 'system',
            'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, hosts e comportamentos maliciosos.'
        },
        {
            'role': 'user',
            'content': prompt
        },
        {
          'role': 'user',
          'content': combined_content
        }
    ]

    print(f"\n=========>> Analisando e gerando relatório...\n")
    full_response = []
    try:
        for part in client.chat('gpt-oss:120b-cloud', messages=message, stream=True):
          content = part['message']['content']
          full_response.append(content)
    except Exception as e:
        print(f"\n\nErro ao comunicar com o modelo de IA: {e}")
        sys.exit(1)

    print(f"\n\n--- Fim da Análise ---")

    with open(f'./reports/{report_filename}', "w", encoding="utf-8") as f:
        f.write("".join(full_response))
    
    with open(f'./reports/{json_filename}', "w", encoding="utf-8") as f:
        f.write(combined_content)

    print(f"[+] Relatório salvo com sucesso em: /reports/{report_filename}")
    print(f"[+] Dados coletados salvo com sucesso em: {json_filename}")
    full_report_path = f'./reports/{report_filename}'
    full_data_path = f'./reports/{json_filename}'
    files.append(full_report_path)
    files.append(full_data_path)

    return files

