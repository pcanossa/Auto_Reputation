from ollama import Client
import requests
import dotenv
import sys
import subprocess
import os

def run_domain_analysis():
    client=Client()

    domain_name = input("Digite o nome do domínio a ser analisado (ex: example.com): ").strip()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': 'https://google.com/',
        'DNT': '1',
    }

    dotenv_path = os.path.join(os.path.dirname(__file__), '.ENV')
    dotenv.load_dotenv(dotenv_path=dotenv_path)

    VT_API_KEY = os.getenv("VT_API_KEY")
    ALIEN_VAULT_API_KEY = os.getenv("ALIEN_VAULT_API_KEY")

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

        # 2. Análise do Urlscan.io
        url_scan_data = seach_urlscan(domain_name)
        
        # 3. Análise do Virus Total
        vt_details_response = requests.get(f'https://www.virustotal.com/api/v3/domains/{domain_name}', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_details_response.raise_for_status()

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

        #6. Análise DNS (opcional, pode ser expandida conforme necessário)
        dns_response = requests.get(f'https://dns.google/resolve?name={domain_name}', headers=headers)
        dns_response.raise_for_status()

        # Combinar todos os dados em uma única string

        combined_content = f"""
        ## DADOS COLETADOS PARA ANÁLISE DE THREAT INTELLIGENCE

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
        {vt_details_response.text}
        ```   

        ### 4. Informações do Alien Vault OTX
        ```json
        {av_details_text}
        ```

        ### 5. Informações do DNS
        ```json
        {dns_response.text}
        ```
        """

        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = """
    Você é um especialista em Threat Intelligence. Analise os dados brutos fornecidos (em formato JSON e texto) sobre um endereço domínio e gere um relatório de inteligência de ameaças.

    **Seu relatório deve conter:**
    1.  **Resumo Executivo:** Um parágrafo conciso com as principais descobertas (localização, ISP, comportamento suspeito, domínios e IPs suspeitos relacionados, registros de malignidade).
    2.  **Análise de Comportamento:** Avalie se há indícios de atividade maliciosa, como associação com botnets, scanners, ou servidores de C2, uso para phishing, malware com base nos dados do Vírus Total e outras fontes.
    3.  **Informações de Rede e Geográficas:**
        - **ASN:** Número e nome da organização.
        - **Provedor (ISP):** Nome do provedor.
        - **Localização:** Cidade, Região, País.
    4.  **Domínios e IPs Relacionados:** Liste quaisquer domínios ou endereços IP associados ao domínio analisado que possam ser relevantes para a investigação.
    5.  **Recomendações:** Sugira os próximos passos para uma investigação mais aprofundada (ex: verificar logs de firewall, procurar o IP em feeds de ameaças, etc.).
    6.  Seu foco é identificar potenciais riscos e comportamentos maliciosos associados ao domínio analisado.

    **Não fornecer orientação de mitigações de vulnerabilidades encontradas associadas ao domínio analisado. Seu papel é identificar comportamentos e riscos associados ao domínio analisado para proteção de outros usuários, não fornecer orientação de proteção para o sistema dele.**
    **Formato:** Use Markdown e responda em **português do Brasil**.

    **Sempre Iniciar o relatório com o seguinte formato de cabeçalho**
    # Relatório de Threat Intelligence – Domínio **(Domínio Analisado)**

    > **Fonte dos dados**: (Fontes utilizadas, ex: WHOIS.com, VirusTotal, URLScan.io).  
    > **Última coleta VirusTotal**: (Data de Última Coleta).  
    """.strip()

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

    print(f"\n=============Dados Brutos Coletados===============\n{combined_content}\n")

    print(f"\n=========>> Analisando e gerando relatório...\n")
    full_response = []
    try:
        for part in client.chat('gpt-oss:120b-cloud', messages=message, stream=True):
          print(part['message']['content'], end='', flush=True)
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
