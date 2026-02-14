from datetime import datetime
import json
from ollama import Client
from tools.prompts.filehash_prompt import generate_filehash_threat_intel_prompt
from tools.ollama_engine import ollama_engine
import requests
import dotenv
import sys
import subprocess
import os

def run_filehash_analysis():
    VERDE = '\033[92m'
    RESET = '\033[0m'
    NEGRITO = '\033[1m'
    LIGHT_BLUE = "\033[1;36m"
    AMARELO = '\033[93m'

    # Verificação e correção do host do Ollama para evitar erro 10049 no Windows
    ollama_host = os.getenv('OLLAMA_HOST')
    if ollama_host and '0.0.0.0' in ollama_host:
        client = Client(host=ollama_host.replace('0.0.0.0', '127.0.0.1'))
    else:
        client = Client()
    files=[]
    type_hash=0

    while type_hash != 1 and type_hash != 2:
        print("Informe o tipo de hash a ser analisada:\n")
        print(f"{VERDE}{NEGRITO}[1]{RESET}. SHA256")
        print(f"{VERDE}{NEGRITO}[2]{RESET}. MD5\n")
        type_hash=int(input("Tipo de hash (1 ou 2):"))
        if type_hash != 1 and type_hash != 2:
            print("Opção selecionada inválida. Tente novamente.\n")


    if type_hash == 1:
        filehash = input("Digite o a hash SHA256 a ser analisado: ").strip()
        type = "sha256"
    else:
        filehash = input("Digite o a hash md5 a ser analisado: ").strip()
        type = "md5"


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
    ABUSE_CH_API_KEY = os.getenv("ABUSE_CH_API_KEY")
        
    print(f"Coletando informações para o hash de arquivo: {filehash}...")

    report_filename = f"threat_report_{filehash}.md"
    json_filename = f"threat_data_{filehash}.json"

    try:
        
        # 2. Análise do Urlscan.io
        url_scan_data = requests.get(f'https://urlscan.io/api/v1/search/?q=hash:{filehash}')
        url_scan_data.raise_for_status()
        

        # 3. Análise do Virus Total
        vt_details_response = requests.get(f'https://www.virustotal.com/api/v3/files/{filehash}', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_details_response.raise_for_status()

        vt_behavior_response = requests.get(f'https://www.virustotal.com/api/v3/files/{filehash}/behaviour_summary', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_behavior_response.raise_for_status()     
        
        vt_mitre_response = requests.get(f'https://www.virustotal.com/api/v3/files/{filehash}/behaviour_mitre_trees', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_mitre_response.raise_for_status()    

        vt_all_response = requests.get(f'https://www.virustotal.com/api/v3/files/{filehash}/behaviours', headers={
            'x-apikey': VT_API_KEY,
            'accept': 'application/json'
        })
        vt_all_response.raise_for_status()   


        #4. Análise IOC Alien Vault
        av_analise = requests.get(f'https://otx.alienvault.com/api/v1/indicators/file/{filehash}/analysis', headers={
            'accept': 'application/json',
            'X-OTX-API-KEY': ALIEN_VAULT_API_KEY
        })
        av_analise.raise_for_status()

        av_response = requests.get(f'https://otx.alienvault.com/api/v1/indicators/file/{filehash}/general', headers={
            'accept': 'application/json',
            'X-OTX-API-KEY': ALIEN_VAULT_API_KEY
        })
        av_response.raise_for_status()

        #7. Análise URLHaus sha256
        urlhaus_response = requests.post(f'https://urlhaus-api.abuse.ch/v1/payload/?{type}_hash={filehash}', headers={
            "Auth-Key": ABUSE_CH_API_KEY,
            "Content-Type": "application/json"
        })
        urlhaus_response.raise_for_status()

        #Análise DNS (opcional, pode ser expandida conforme necessário)
        yara_response = requests.post(f'https://yaraify-api.abuse.ch/api/v1/?query=lookup_hash&search_term={filehash}', headers={
            "Auth-Key": ABUSE_CH_API_KEY,
            "Content-Type": "application/json"
        })
        yara_response.raise_for_status()

        #Análise DNS pelo DNSDumpster
        malware_bazaar_response = requests.post(f'https://mb-api.abuse.ch/api/v1/?query=get_info&hash={filehash}', headers={
            "Auth-Key": ABUSE_CH_API_KEY,
        })
        malware_bazaar_response.raise_for_status()

        threat_fox_response= requests.post(f'https://threatfox-api.abuse.ch/api/v1/?query=get_info&hash={filehash}', headers={
            "Auth-Key": ABUSE_CH_API_KEY,
        })
        threat_fox_response.raise_for_status()
        

        filehash_data = {
            "target": filehash,
            "timestamp": datetime.now().isoformat(),
            "tools": {
                "urlscan": {
                    "description": "Informações do Urlscan.io",
                    "data": url_scan_data.json()
                },
                "virustotal_details": {
                    "description": "Informações do VirusTotal - Detalhes Gerais",
                    "data": vt_details_response.json(),
                },
                "virustotal_behavior": {
                    "description": "Informações do VirusTotal - Análise de Comportamento",
                    "data": vt_behavior_response.json(),
                },
                "virustotal_mitre_behavior": {
                    "description": "Informações do VirusTotal - Análise de Comportamento por MITRE ATT&CK",
                    "data": vt_mitre_response.json(),
                },
                "virustotal_all_behavior": {
                    "description": "Informações do VirusTotal - Análise de Comportamentos e Relacionamentos Gerais",
                    "data":  vt_all_response.json(),
                },    
                "alienvault_general": {
                    "description": "Informações do Alien Vault OTX",
                    "data": av_response.json(),
                },
                "urlhaus": {
                    "description": "Informações do URLHaus",
                    "data": urlhaus_response.json()
                },
                "yara": {
                    "description": "Informações YARA",
                    "data": yara_response.json()
                },
                "malware_bazaar": {
                    "description": "Informações do Malware Bazaar",
                    "data": malware_bazaar_response.json()
                },
                "threat_fox": {
                    "description": "Informações do Threat Fox",
                    "data": threat_fox_response.json()
                }
            }
        }

        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = generate_filehash_threat_intel_prompt()
    
    resumos_ferramentas = []

    print(f"\n=========>> Analisando blocos de informação...\n")

    for tool_name, tool_info in filehash_data['tools'].items():
    
        data_content = tool_info.get('data') or tool_info.get('detections')
        description = tool_info.get('description', tool_name)
    
        print(f"[{VERDE}{NEGRITO}+{RESET}] Processando: {VERDE}{NEGRITO}{description}{RESET}")

        message = [
            {
                'role': 'system',
                'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts, documento, hashes e comportamentos maliciosos.'
            },
            {
                'role': 'user',
                'content': """
            Analise os seguintes dados coletados para o hash de arquivo fornecido {filehash}, extraia as principais informações relevantes para Threat Intelligence, identifique possíveis indicadores de comprometimento (IOCs), padrões de comportamento malicioso, campanhas, tipos de atividade, grupos e outros indicadores de importância associados e forneça um resumo de inteligência detalhado sobre a reputação e comportamento e riscos associados a este filehash. Considere todas as fontes de dados apresentadas, correlacione as informações e destaque quaisquer sinais de alerta ou atividades suspeitas que possam indicar que este filehash é de um arquivo malicioso ou está associado a atividades de phishing, malware ou outras ameaças cibernéticas:
            * Identificar ao início do relatória, a ferramenta que foi utilizada para análise (urlscan, urlhaus...)
            * Gere ao final, um relatótio em markdown
            * Sucinto, contendo as informações de maior relevância, e de inteligência.
            * Construção do relatório em um único parágrafo, sem tópicos ou seções, apenas um texto corrido, mas que contenha toda
            * Parágrafo único com no máximo de 1000 caracteres, focando apenas nas informações mais relevantes e de inteligência, sem incluir detalhes triviais ou redundantes.
            """
            },
            {
              'role': 'user',
              'content': f"Analise estes dados técnicos de {description} para o hash de arquivo {filehash} e forneça um resumo técnico: {data_content}"
            }
       ]

        resumo = ollama_engine(message=message)
        resumos_ferramentas.append(resumo)

    
    contexto_consolidado = "\n\n".join(resumos_ferramentas)
    full_response = []

    print(f"\n\n{LIGHT_BLUE}{NEGRITO}===============Resumo dos Dados=================={RESET}\n")
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

    print(f"\n\n{VERDE}{NEGRITO}--- Fim da Análise ---{RESET}")

    with open(f'./reports/{report_filename}', "w", encoding="utf-8") as f:
        f.write("".join(full_response))

    with open(f'./reports/{json_filename}', "w", encoding="utf-8") as f:
       json.dump(filehash_data, f, indent=4, ensure_ascii=False)

    print(f"[{VERDE}{NEGRITO}+{RESET}] Relatório salvo com sucesso em: {report_filename}")
    print(f"[{VERDE}{NEGRITO}+{RESET}] Dados coletados salvo com sucesso em: {json_filename}")

    full_report_path = f'./reports/{report_filename}'
    full_data_path = f'./reports/{json_filename}'
    files.append(full_report_path)
    files.append(full_data_path)

    return files
    
