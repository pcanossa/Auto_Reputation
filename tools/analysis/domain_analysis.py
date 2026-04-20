from datetime import datetime
import time
import json
from ollama import Client
from ..prompts.domain_prompt import generate_domain_threat_intel_prompt
from ..others.get_phishing_list import fetch_phishing_lists
from ..others.ollama_engine import ollama_engine
import requests
import dotenv
import sys
import subprocess
import os

def run_domain_analysis():
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

    domain_name = input("Digite o nome do domínio a ser analisado (ex: example.com): ").strip()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Referer': 'https://google.com/',
        'DNT': '1',
    }

    dotenv_path = os.path.join(os.path.dirname(__file__), '../.env')
    dotenv.load_dotenv(dotenv_path=dotenv_path)

    VT_API_KEY = os.getenv("VT_API_KEY")
    ALIEN_VAULT_API_KEY = os.getenv("ALIEN_VAULT_API_KEY")
    DNS_DUMPSTER_API_KEY = os.getenv("DNS_DUMPSTER_API_KEY")
    SECURITY_TRAILS_API_KEY = os.getenv("SECURITY_TRAILS_API_KEY")
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
    SPAMHAUS_USERNAME = os.getenv("SPAMHAUS_USERNAME")
    SPAMHAUS_API_KEY = os.getenv("SPAMHAUS_API_KEY")

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
            ['curl', '-v', '-I', '-o', '/dev/null', ip],
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
    
    print(f"Coletando informações para o domínio: {domain_name}...")

    sanitized_domain = domain_name.replace('.', '_')
    report_filename = f"threat_report_{sanitized_domain}.md"
    json_filename = f"threat_data_{sanitized_domain}.json"

    try:
        # 1. Análise do WHOIS.com
        whois_text = get_cli_whois(domain_name)

        headers_text = get_cli_header(domain_name)

        # 2. Análise do Urlscan.io
        url_scan_data = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{domain_name}')
        url_scan_data.raise_for_status()

           

        urlscan_payload = {
            "url": domain_name,
            "visibility": "public",
        }

        url_scan_scaner_response = requests.post(f'https://urlscan.io/api/v1/scan', headers={
            "api-key": URLSCAN_API_KEY,
            'Content-Type': 'application/json'
        }, json=urlscan_payload)

        if url_scan_scaner_response.status_code == 400:
            print(f"\n[{AMARELO}{NEGRITO}!{RESET}] Scan por URLScan.io não realizado para o domínio {domain_name} -> Não foram encontrados registros de DNS para resolver o domínio.")
            url_scan_scaner_data = {
                "error": "Urlscan.io retornou erro 400 - Domínio não encontrado ou sem registros DNS."
            }

        else:    
            url_scan_scaner_response.raise_for_status()
            scanID = url_scan_scaner_response.json().get('uuid')
            print(f"\n[{AMARELO}{NEGRITO}*{RESET}] Scan iniciado no {VERDE}{NEGRITO}Urlscan.io (ID: {scanID}){RESET}. Aguardando conclusão...")



            url_scan_scaner_data = None
            # Polling para aguardar o resultado (até 90s)
            for _ in range(18):
                time.sleep(5)
                temp_response = requests.get(f'https://urlscan.io/api/v1/result/{scanID}', headers={
                    "api-key": URLSCAN_API_KEY,
                    'Content-Type': 'application/json'
                })
                if temp_response.status_code != 404:
                    url_scan_scaner_data = temp_response.json()
                    break
                
            if url_scan_scaner_data is None:
                url_scan_scaner_data = temp_response.json()

        
        
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

        #7. Análise de certificado cert.sh
        cert_response = requests.get(f'https://crt.sh/?q={domain_name}&output=json', headers=headers)
        if cert_response.status_code != 200:
            cert_data =  {"error": "Erro ao obter dados do cert.sh, tente mais tarde"}
        else:
            cert_data = cert_response.json()

        #Análise DNS (opcional, pode ser expandida conforme necessário)
        dns_response = requests.get(f'https://dns.google/resolve?name={domain_name}', headers=headers)
        dns_response.raise_for_status()

        #Análise DNS pelo DNSDumpster
        dns_dumpster_response = requests.get(f'https://api.dnsdumpster.com/domain/{domain_name}', headers={
            "X-API-Key": DNS_DUMPSTER_API_KEY
        })
        dns_dumpster_response.raise_for_status()

        #Análise em lista de urls phishings conhecidas
        phishing_list_info, phishing_list_info_file = fetch_phishing_lists(domain_name)



        records=[
            "a",
            "aaaa",
            "mx",
            "ns",
            "soa",
            "txt",
        ]
        st_responses = {}
        for r in records:
            try:
                response = requests.get(f'https://api.securitytrails.com/v1/history/{domain_name}/dns/{r}', headers={
                    "apikey": SECURITY_TRAILS_API_KEY
                })
                if response.status_code == 429:
                    st_responses[r] = {
                        "error": "Limite de requisições (quota) atingido para SecurityTrails."
                    }
                else:
                    response.raise_for_status()
                    st_responses[r] = response.json()
            except Exception as e:
                st_responses[r] = {"error": f"Erro na requisição: {str(e)}"}
            time.sleep(1)

        try:
            security_trail_subdomains_reponse = requests.get(f'https://api.securitytrails.com/v1/domain/{domain_name}/subdomains', headers={
                "apikey": SECURITY_TRAILS_API_KEY
            })
            if security_trail_subdomains_reponse.status_code == 429:
                security_trail_subdomains_data = {
                    "error": "Limite de requisições (quota) atingido para SecurityTrails."
                }
            else:
                security_trail_subdomains_reponse.raise_for_status()
                security_trail_subdomains_data = security_trail_subdomains_reponse.json()
        except Exception as e:
            security_trail_subdomains_data = {"error": f"Erro na requisição: {str(e)}"}


        spamhaus_get_token = requests.post('https://api.spamhaus.org/api/v1/login', json={
            "username": SPAMHAUS_USERNAME,
            "password": SPAMHAUS_API_KEY,
            "realm": "intel"
        })
        spamhaus_get_token.raise_for_status()
        spamhaus_token = spamhaus_get_token.json().get('token')
        print(spamhaus_token)

        spamhaus_get_hashes = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain_name}/malware/hashes", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_get_malwares_urls = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain_name}/malware/urls", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_get_hostnames = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain_name}/hostnames", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_get_general = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain_name}", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_get_contexts = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain_name}/contexts", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_get_dimensions = requests.get(f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{domain_name}/dimensions", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_dimensions = requests.get("https://api.spamhaus.org/api/intel/v2/domains/dimensions", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)

        spamhaus_tags = requests.get("https://api.spamhaus.org/api/intel/v2/domains/tags", headers={
            "Authorization": f"Bearer {spamhaus_token}"
        })
        time.sleep(5)


        spamhaus_data = {
            "general": spamhaus_get_general.json() if spamhaus_get_general.status_code == 200 else {"info": "Não encontrado"},
            "contexts": spamhaus_get_contexts.json() if spamhaus_get_contexts.status_code == 200 else {"info": "Não encontrado"},
            "dimensions": spamhaus_get_dimensions.json() if spamhaus_get_dimensions.status_code == 200 else {"info": "Não encontrado"},
            "dimensions_context": spamhaus_dimensions.json() if spamhaus_dimensions.status_code == 200 else {"info": "Não encontrado"},
            "tags": spamhaus_tags.json() if spamhaus_tags.status_code == 200 else {"info": "Não encontrado"},
        }

        spamhaus_malwares = {
            "hashes": spamhaus_get_hashes.json() if spamhaus_get_hashes.status_code == 200 else {"info": "Não encontrado"},
            "urls": spamhaus_get_malwares_urls.json() if spamhaus_get_malwares_urls.status_code == 200 else {"info": "Não encontrado"},
        }

        domain_data = {
            "target": domain_name,
            "timestamp": datetime.now().isoformat(),
            "tools": {
                "whois": {
                    "description": "Informações do WHOIS",
                    "data": whois_text
                },
                "urlscan_general": {
                    "description": "Informações do Urlscan.io - Busca por domínio",
                    "data": url_scan_data.json()
                },
                "urlscan_scaner": {
                    "description": "Informações do Urlscan.io - Resultado do scanner",
                    "data": url_scan_scaner_data
                },
                "virustotal_general": {
                    "description": "Informações do VirusTotal - Informações gerais",
                    "data": vt_details_response.json(),
                },
                "virustotal_comments": {
                    "description": "Informações do VirusTotal - Comentários",
                    "data": vt_comments_response.json(),
                },
                "virustotal_files": {
                    "description": "Informações do VirusTotal - Arquivos",
                    "data": vt_files_response.json()
                },
                "alienvault": {
                    "description": "Informações do Alien Vault OTX",
                    "data": av_response.json()
                },
                "dns": {
                    "description": "Informações do DNS",
                    "data": dns_response.json()
                },
                "curl_headers": {
                    "description": "Cabeçalhos HTTP via cURL",
                    "data": headers_text
                },
                "ssl_cert": {
                    "description": "Informações do certificado SSL/TLS",
                    "data": cert_data
                },
                "dns_dumpster": {
                    "description": "Informações do DNSDumpster",
                    "data": dns_dumpster_response.json()
                },
                "security_trail_dns_a": {
                    "description": "Informações do SecurityTrails - DNS A Records",
                    "data": st_responses['a']
                },
                "security_trail_dns_aaaa": {
                    "description": "Informações do SecurityTrails - DNS AAAA Records",
                    "data": st_responses['aaaa']
                },
                "security_trail_dns_mx": {
                    "description": "Informações do SecurityTrails - DNS MX Records",
                    "data": st_responses['mx']
                },
                "security_trail_dns_ns": {
                    "description": "Informações do SecurityTrails - DNS NS Records",
                    "data": st_responses['ns']
                },
                "security_trail_dns_soa": {
                    "description": "Informações do SecurityTrails - DNS SOA Records",
                    "data": st_responses['soa']
                },
                "security_trail_dns_txt": {
                    "description": "Informações do SecurityTrails - DNS TXT Records",
                    "data": st_responses['txt']
                },
                "security_trail_subdomains": {
                    "description": "Informações do SecurityTrails - Subdomínios",
                    "data": security_trail_subdomains_data
                },
                "phishing_army": {
                    "description": "Verificação em listas de phishing",
                    "data": phishing_list_info
                },
                "spamhaus_general": {
                    "description": "Informações do Spamhaus - Reputação",
                    "data": spamhaus_data
                },
                "spamhaus_malware_hashes": {
                    "description": "Informações do Spamhaus - Hashes e urls malware associados",
                    "data": spamhaus_malwares
                },
                "spamhaus_hosts_associates": {
                    "description": "Informações do Spamhaus - Hosts associados",
                    "data": spamhaus_get_hostnames.json() if spamhaus_get_hostnames.status_code == 200 else {"info": "Não encontrado"}
                }
            }
        }

        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = generate_domain_threat_intel_prompt()
    
    resumos_ferramentas = []

    print(f"\n=========>> Analisando blocos de informação...\n")

    for tool_name, tool_info in domain_data['tools'].items():
    
        data_content = tool_info.get('data') or tool_info.get('detections')
        description = tool_info.get('description', tool_name)
    
        print(f"[{VERDE}{NEGRITO}+{RESET}] Processando: {VERDE}{NEGRITO}{description}{RESET}")

        message = [
            {
                'role': 'system',
                'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, domínios, hosts e comportamentos maliciosos.'
            },
            {
                'role': 'user',
                'content': """
            Analise os seguintes dados coletados para o domínio {domain_name}, extraia as principais informações relevantes para Threat Intelligence, identifique possíveis indicadores de comprometimento (IOCs), padrões de comportamento malicioso e forneça um resumo detalhado sobre a reputação e riscos associados a este domínio. Considere todas as fontes de dados apresentadas, correlacione as informações e destaque quaisquer sinais de alerta ou atividades suspeitas que possam indicar que este domínio é malicioso ou está associado a atividades de phishing, malware ou outras ameaças cibernéticas:
            * Identificar ao início do relatória, a ferramenta que foi utilizada para análise (urlscan, whois...)
            * Gere ao final, um relatótio em markdown
            * Sucinto, contendo as informações de maior relevância, e de inteligência.
            * Construção do relatório em um único parágrafo, sem tópicos ou seções, apenas um texto corrido, mas que contenha toda
            * Parágrafo único com no máximo de 1000 caracteres, focando apenas nas informações mais relevantes e de inteligência, sem incluir detalhes triviais ou redundantes.
            * Evite incluir informações que não sejam diretamente relevantes para a avaliação de risco do domínio.
            """
            },
            {
              'role': 'user',
              'content': f"Analise estes dados técnicos de {description} para o domínio {domain_name} e forneça um resumo técnico: {data_content}"
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
       json.dump(domain_data, f, indent=4, ensure_ascii=False)

    print(f"[{VERDE}{NEGRITO}+{RESET}] Relatório salvo com sucesso em: {report_filename}")
    print(f"[{VERDE}{NEGRITO}+{RESET}] Dados coletados salvo com sucesso em: {json_filename}")

    full_report_path = f'./reports/{report_filename}'
    full_data_path = f'./reports/{json_filename}'
    files.append(full_report_path)
    files.append(full_data_path)
    files.append(phishing_list_info_file)

    return files, sanitized_domain
    

