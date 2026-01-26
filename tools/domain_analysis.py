from datetime import datetime
from ollama import Client
from tools.prompts.domain_prompt import generate_domain_threat_intel_prompt
import requests
import dotenv
import sys
import subprocess
import os

def run_domain_analysis():
    client=Client()
    files=[]

    domain_name = input("Digite o nome do domínio a ser analisado (ex: example.com): ").strip()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': 'https://google.com/',
        'DNT': '1',
    }

    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    dotenv.load_dotenv(dotenv_path=dotenv_path)

    VT_API_KEY = os.getenv("VT_API_KEY")
    ALIEN_VAULT_API_KEY = os.getenv("ALIEN_VAULT_API_KEY")
    DNS_DUMPSTER_API_KEY = os.getenv("DNS_DUMPSTER_API_KEY")

    def get_cli_whois(domain):
        process = subprocess.Popen(
            ['whois', domain],
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
            ['curl', '-v', '-o /dev/null', ip],
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
    
    def seach_urlscan(domain):
        url_scan_reponse = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{domain_name}')
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

    print(f"Coletando informações para o domínio: {domain_name}...")

    sanitized_domain = domain_name.replace('.', '_')
    report_filename = f"threat_report_{sanitized_domain}.md"
    json_filename = f"threat_data_{sanitized_domain}.txt"

    try:
        # 1. Análise do WHOIS.com
        whois_text = get_cli_whois(domain_name)

        headers_text = get_cli_header(domain_name)

        # 2. Análise do Urlscan.io
        url_scan_data = seach_urlscan(domain_name)
        
        # 3. Análise do Virus Total
        vt_details_response = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain_name}', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_details_response.raise_for_status()

        vt_comments_response = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain_name}/relationships/related_comments?limit=10', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_comments_response.raise_for_status()

        vt_files_response = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain_name}/communicating_files?limit=10', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_files_response.raise_for_status()

        #4. Análise IOC Alien Vault
        av_response = requests.get(f'https://otx.alienvault.com/api/v1/indicators/domain/{domain_name}/general', headers={
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

        #7. Análise de certificado cert.sh
        cert_response = requests.get(f'https://crt.sh/?q={domain_name}&output=json', headers=headers)
        cert_response.raise_for_status()

        #Análise DNS (opcional, pode ser expandida conforme necessário)
        dns_response = requests.get(f'https://dns.google/resolve?name={domain_name}', headers=headers)
        dns_response.raise_for_status()

        #Análise DNS pelo DNSDumpster
        dns_dumpster_response = requests.get(f'https://api.dnsdumpster.com/domain/{domain_name}', headers={
            "X-API-Key": DNS_DUMPSTER_API_KEY
        })
        dns_dumpster_response.raise_for_status()


        # Combinar todos os dados em uma única string

        combined_content = f"""
        ## DADOS COLETADOS PARA ANÁLISE DE THREAT INTELLIGENCE

        TIMESTAMP: {datetime.now().isoformat()}

        ### 1. Informações do WHOIS
        ```html
        {whois_text}
        ```

        ### 2. Informações do Urlscan.io
        ```json
        {url_scan_data}
        ```

        ### 3. Informações do VirusTotal
        ```json
        detecções = {vt_details_response.text}
        comentários da comunidade = {vt_comments_response.text}
        arquivos comunicados = {vt_files_response.text}
        ```   

        ### 4. Informações do Alien Vault OTX
        ```json
        {av_details_text}
        ```

        ### 5. Informações do DNS
        ```json
        {dns_response.text}
        ```

        ### 6. Cabeçalhos HTTP via cURL
        ```html
        {headers_text}
        ```

        ### 7. Informações do certificado SSL/TLS
        ```json
        {cert_response.text}
        ```

        ### 8. Informações do DNSDumpster
        ```json
        {dns_dumpster_response.text}
        ```
        """

        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = generate_domain_threat_intel_prompt()

    message = [
        {
            'role': 'system',
            'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'
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

    print(f"[+] Relatório salvo com sucesso em: {report_filename}")
    print(f"[+] Dados coletados salvo com sucesso em: {json_filename}")

    full_report_path = f'./reports/{report_filename}'
    full_data_path = f'./reports/{json_filename}'
    files.append(full_report_path)
    files.append(full_data_path)

    return files, sanitized_domain

    
