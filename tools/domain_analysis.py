from datetime import datetime
from ollama import Client
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
        """

        
    except requests.exceptions.HTTPError as e:
        print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
        print(f"URL que falhou: {e.request.url}")
        sys.exit(1)

    prompt = f"""
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
    > **Timestamp da Análise**: {datetime.now().isoformat()}. 

    ## MODELO DE RELATÓRIO

    ## 1. Resumo Executivo
    O domínio está registrado sob a IANA (RESERVED‑Internet Assigned Numbers Authority) e não possui um registrador comercial típico. Não há informações de ISP / ASN associadas ao domínio em si; os endereços IP resolvidos pertencem a múltiplas redes (Amazon AWS, Google Cloud, provedores de hospedagem genéricos). Embora o VirusTotal indique “benigno” (0 malicious / 0 suspicious, 66 harmless), o domínio aparece em *mais de 30 pulsos* da OTX que o relacionam a **botnets, scanners, phishing, C2s e campanhas de malware** (ex.: Mirai, Pegasus, Emotet, Tofsee, etc.). Diversos endereços IPv4 (23.192.228.84, 23.215.0.136, 23.215.0.138, 23.220.75.245, 23.220.75.232, 23.192.228.80) são resolvidos pelo DNS e são referenciados em múltiplas análises de ameaças. O domínio pode ser usado como *infrastructure-as-a-service* por atores maliciosos (e.g., hospedagem de arquivos, redirecionamento de tráfego, C2). Não há evidência de comprometimento direto de usuários finais, mas a presença em campanhas de **phishing** e **malware distribution** indica que ele pode ser incluído em listas de bloqueio e observação.

    ---

    ## 2. Análise de Comportamento
    | Fonte | Evidência | Interpretação |
    |------|------------|---------------|
    | **VirusTotal** | 0 malicious, 0 suspicious, 66 harmless; certificação DNSSEC; certificado **GlobalSign** (SHA‑256). | O domínio ainda não foi marcado como malicioso pelos scanners tradicionais, mas a ausência de detecção não garante segurança. |
    | **Urlscan.io** (várias execuções) | Diversas requisições HTTP/HTTPS para endereços IP diferentes, alguns marcados como “suspicious” pelos usuários. | O domínio é usado como webhook ou redirecionamento para múltiplos servidores – padrão de infraestrutura de **C2** ou **delivery**. |
    | **AlienVault OTX – Pulses** | - Pulse “Operation Endgame” (botnet, Pegasus, Mirai, Emotet). <br>- “Microsoft Phishing Collection”. <br>- “Cerber Ransomware”, “Mirai Communication Networks”. <br>- “Trojans, DDoS, VPNFilter, DNSRat”. | O domínio aparece em *bulky intelligence feeds* que agrupam indicadores de ataques avançados. Possível **shared hosting** para diferentes campanhas. |
    | **DNS** | 6 A‑records diferentes (todos dentro do bloco 23. x.x.x). | Distribuição geográfica e de rede típica de **cloud providers**, facilitando disponibilidade e resiliência para atores maliciosos. |
    | **Whois** | Registrado em 1995, via **IANA** (sem contato público). | Domínio antigo, possivelmente usado como “placeholder” ou **sandbox** por ferramentas automáticas de teste. |

    **Táticas/Procedimentos (ATT&CK) observados nos pulsos associados**  

    - **T1071 – Application Layer Protocol (HTTP/DNS)** – uso de domínios legítimos como capa.  
    - **T1045 – Software Packing** – arquivos UPX, ofuscados.  
    - **T1027 – Obfuscated Files or Information** – presença de scripts/payloads ofuscados.  
    - **T1105 – Ingress Tool Transfer** – entrega de arquivos maliciosos via HTTP/HTTPS.  
    - **T1192 – Spearphishing Link** – links de phishing apontando para `example.com`.  
    - **T1095 – Non‑Application Layer Protocol** – uso de DNS para C2.  
    - **T1486 – Data Encrypted for Impact** – ransomware associado em alguns pulsos.  

    ---

    ## 3. Informações de Rede e Geográficas
    | Campo | Valor |
    |-------|-------|
    | **ASN** | Não definido para o domínio; os IPs apontam para diferentes AS (ex.: AS16509 – Amazon, AS15169 – Google). |
    | **ISP / Provedor** | Varia conforme o IP resolvido (AWS, Google Cloud, outros provedores de hospedagem). |
    | **País / Região** | Todos os IPs reportados estão alocados nos **Estados Unidos** (Arizona / California). |
    | **Endereços IPv4** | 23.192.228.84, 23.215.0.136, 23.215.0.138, 23.220.75.245, 23.220.75.232, 23.192.228.80 |
    | **IPv6** | Não há registros de AAAA. |
    | **DNSSEC** | Sim – assinatura DS = 370 / 13 / 2. |

    ---

    ## 4. Domínios e IPs Relacionados
    - **Domínios citados em pulsos** (exemplos representativos): `moneytipstv.com`, `kayascience.com`, `email-supports.im`, `online-app.muchine.info`, `agri.com`, `gopdf.com`, `example.org` (utilizados como “sandbox” em análises).  
    - **IPs frequentemente associados** nos Pulses: `23.192.228.84`, `23.215.0.136`, `23.215.0.138`, `23.220.75.245`, `23.220.75.232`, `23.192.228.80`, além de endereços de **Cloudflare** (2600:1406::), **Google** (2600:1408::), entre outros.  

    > **Observação:** A lista completa contém milhares de indicadores; o foco aqui são os que aparecem diretamente ligados ao domínio `example.com`.

    ---

    ## 5. Recomendações de Ações de Investigação
    1. **Monitoramento de tráfego DNS** – registre consultas ao domínio `example.com` nos logs internos (SIEM, DNS firewall). Alertas para resoluções a IPs fora do escopo corporativo ou em horários anômalos.  
    2. **Correlações de logs de proxy / web** – procure por requisições HTTP(S) a `example.com` ou sub‑paths associados (ex.: `/login`, `/download`).  
    3. **Bloqueio de indicadores** – adicione os 6 A‑records acima em listas de bloqueio (firewall, Web‑proxy, DNS sinkhole).  
    4. **Threat hunting** – busque por arquivos ou hashes que aparecem nos Pulses relacionados (ex.: SHA‑256 de arquivos “UPX‑packed”, scripts JavaScript maliciosos) nos endpoints da organização.  
    5. **Verificação de e‑mail** – como ele aparece em “Microsoft Phishing Collection”, implemente regras de deteção de e‑mails contendo links para `example.com`.  
    6. **Enriquecimento adicional** – consulte bases de inteligência que fornecem **ASN** e **geolocalização** para cada IP, para validar se pertencem a cloud providers (ex.: AWS, GCP) ou a redes de ameaças conhecidas.  
    7. **Avaliação de Certificado** – embora o certificado SSL seja emitido por DigiCert (legítimo), verifique a validade e a cadeia de confiança – alguns atores utilizam certificados válidos para legitimar C2.  

    ---

    ## 6. Conclusão
    `example.com` não apresenta comportamento malicioso direto nos scanners de antivírus, porém **está fortemente correlacionado** com múltiplas campanhas de ameaças avançadas (botnets, phishing, ransomware). A presença de registros DNSSEC e um certificado válido não elimina o risco de ser usado como **capa** para infraestrutura de ataque. Recomenda‑se **tratá‑lo como risco médio‑alto**, monitorando ativamente as resoluções DNS, bloqueando os IPs associados e investigando eventuais tráfegos ou artefatos que façam referência a ele dentro do ambiente corporativo.  

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

    

