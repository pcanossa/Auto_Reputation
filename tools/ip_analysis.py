from datetime import datetime
import subprocess
import json
import shodan
from ollama import Client
from tools.prompts.ip_prompt import generate_ip_threat_intel_prompt
from tools.ollama_engine import ollama_engine
import requests
import dotenv
import sys
import os
import hashlib

def run_ip_analysis():
    # Verificação e correção do host do Ollama para evitar erro 10049 no Windows
    ollama_host = os.getenv('OLLAMA_HOST')
    if ollama_host and '0.0.0.0' in ollama_host:
        client = Client(host=ollama_host.replace('0.0.0.0', '127.0.0.1'))
    else:
        client = Client()
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

    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    VT_API_KEY = os.getenv("VT_API_KEY")
    ALIEN_VAULT_API_KEY = os.getenv("ALIEN_VAULT_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    SCAMNALYTICS_API_KEY = os.getenv("SCAMNALYTICS_API_KEY")
    VPNAPI_KEY = os.getenv("VPNAPI_KEY")

    shodan_api = shodan.Shodan(SHODAN_API_KEY)
    
    print(f"Coletando informações para o IP: {ip}...")

    sanitized_ip = ip.replace('.', '_')
    report_filename = f"threat_report_{sanitized_ip}.md"
    json_filename = f"threat_data_{sanitized_ip}.json"

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


    try:

        shodan_response = shodan_api.host(ip)

        ipinfo_response = requests.get(f'https://ipinfo.io/{ip}/json', headers=headers)
        ipinfo_response.raise_for_status() 

        url_scan_reponse = requests.get(f'https://urlscan.io/api/v1/search/?q=ip:{ip}')
        url_scan_reponse.raise_for_status()

        vt_details_response = requests.get(f'https://www.virustotal.com/api/v3/search?query={ip}', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_details_response.raise_for_status()

        vt_comments_response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/relationships/related_comments?limit=10', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_comments_response.raise_for_status()

        vt_files_response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files?limit=10', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_files_response.raise_for_status()

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

        api_key = SCAMNALYTICS_API_KEY
        scamnalytics_data = requests.get(f'https://api11.scamalytics.com/v3/pcanossa/?key={api_key}&ip={ip}')
        scamnalytics_data.raise_for_status()

        vpanapi_response = requests.get(f'https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}')
        vpanapi_response.raise_for_status()

        ip_data = {
            "target": ip,
            "timestamp": datetime.now().isoformat(),
            "tools": {
                "whois": {
                    "description": "Informações do WHOIS",
                    "data": whois_text
                },
                "urlscan": {
                    "description": "Informações do Urlscan.io",
                    "data": url_scan_reponse.json()
                },
                "virustotal": {
                    "description": "Informações do VirusTotal",
                    "detections": vt_details_response.json(),
                    "comments": vt_comments_response.json(),
                    "files": vt_files_response.json()
                },
                "alienvault": {
                    "description": "Informações do Alien Vault OTX",
                    "data": av_response.json()
                },
                "shodan": {
                    "description": "Informações do Shodan",
                    "data": shodan_response
                },    
                "curl_headers": {
                    "description": "Cabeçalhos HTTP via cURL",
                    "data": headers_text
                },
                "ipinfo": {
                    "description": "Informações do IPInfo.io",
                    "data": ipinfo_response.json()
                },
                "abuse_ipdb": {
                    "description": "Informações do AbuseIPDB",
                    "data": ipdb_response.json()
                },
                "scamalytics": {
                    "description": "Verificação do Scamalytics",
                    "data": scamnalytics_data.json()
                },
                "vpnapi": {
                    "description": "Informações do VPNAPI",
                    "data": vpanapi_response.json()
                }
            }
        }
        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = generate_ip_threat_intel_prompt()

    resumos_ferramentas = []

    print(f"\n=========>> Analisando blocos de informação...\n")

    for tool_name, tool_info in ip_data['tools'].items():
    
        data_content = tool_info.get('data') or tool_info.get('detections')
        description = tool_info.get('description', tool_name)
    
        print(f"[+] Processando: {description}")

        message = [
            {
                'role': 'system',
                'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'
            },
            {
                'role': 'user',
                'content': """
            Analise os seguintes dados coletados para o IP {ip_address}, extraia as principais informações relevantes para Threat Intelligence, identifique possíveis indicadores de comprometimento (IOCs), padrões de comportamento malicioso e forneça um resumo detalhado sobre a reputação e riscos associados a este IP. Considere todas as fontes de dados apresentadas, correlacione as informações e destaque quaisquer sinais de alerta ou atividades suspeitas que possam indicar que este IP é malicioso ou está associado a atividades de phishing, malware ou outras ameaças cibernéticas:
            * Identificar ao início do relatória, a ferramenta que foi utilizada para análise (urlscan, whois, etc..)
            * Gere ao final, um relatótio em markdown
            * Sucinto, contendo as informações de maior relevância, e de inteligência.
            * Inclua informações geoespaciais do IP quando presente (latitude, longitude, localização)
            * Construção do relatório em um único parágrafo, sem tópicos ou seções, apenas um texto corrido, mas que contenha toda
            * Parágrafo único com no máximo de 700 caracteres, focando apenas nas informações mais relevantes e de inteligência, sem incluir detalhes triviais ou redundantes.
            * Evite incluir informações que não sejam diretamente relevantes para a avaliação de risco do domínio.
            """
            },
            {
              'role': 'user',
              'content': f"Analise estes dados técnicos de {description} para o IP {ip} e forneça um resumo técnico: {data_content}"
            }
       ]

        resumo = ollama_engine(message=message)
        resumos_ferramentas.append(resumo)
    
    contexto_consolidado = "\n\n".join(resumos_ferramentas)
    full_response = []
    print("\n\n===============Resumo dos Dados==================\n")
    print(f"{contexto_consolidado}\n")
    print(f"\n=========>> Analisando e gerando relatório...\n")


    final_message = [
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
          'content': contexto_consolidado
        }
    ] 

    try:
        full_response = ollama_engine(message=final_message)
    except Exception as e:
        print(f"\n\nErro ao comunicar com o modelo de IA: {e}")
        sys.exit(1)

    print(f"\n\n--- Fim da Análise ---")

    with open(f'./reports/{report_filename}', "w", encoding="utf-8") as f:
        f.write("".join(full_response))
    
    with open(f'./reports/{json_filename}', "w", encoding="utf-8") as f:
        json.dump(ip_data, f, indent=4, ensure_ascii=False)

    print(f"[+] Relatório salvo com sucesso em: /reports/{report_filename}")
    print(f"[+] Dados coletados salvo com sucesso em: {json_filename}")
    full_report_path = f'./reports/{report_filename}'
    full_data_path = f'./reports/{json_filename}'
    files.append(full_report_path)
    files.append(full_data_path)

    return files, sanitized_ip
