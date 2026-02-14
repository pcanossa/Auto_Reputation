from datetime import datetime

def generate_filehash_threat_intel_prompt():

    prompt = f"""
    Você é um especialista em Threat Intelligence. Analise os dados brutos fornecidos (em formato JSON e texto) sobre um endereço domínio e gere um relatório de inteligência de ameaças.

    **Seu relatório deve conter:**
    1.  **Resumo Executivo:** Um parágrafo conciso com as principais descobertas (grupos de atividades maliciosas relacionados, camapnhas relacionadas, registros de malignidade, comportamento suspeito, domínios e IPs suspeitos relacionados, registros de malignidade).
    2.  **Análise de Comportamento:** Avalie se há indícios de atividade maliciosa, como associação com botnets, scanners, ou servidores de C2, uso para phishing, comunicaçao com servidores C2, extração de dados, criptografia de dados, malware com base nos dados das fontes fornecidas.
    3.  **Informações de Campanhas associadas (Se houver):**
        - **Nome de Arquivos:** Nome de arquivos associados à hash de arquivo analisada.
        - **Tipo:** de Arquivo Associado (script, js,, executável, exe...)
        - **Grupo:** Nome da organização.
        - **Alvo:** Alvos da campanha.
        - **Localização:** Localização de campanha.
        - **Classe:** Classe de atividade do malware (infostealer, RAT, Ransoware, etc.)
        - **Objetivo:** Objetivo da camapanha.
    4.  **Domínios e IPs Relacionados:** Liste quaisquer domínios ou endereços IP associados ao filehash analisado que possam ser relevantes para a investigação.
    5.  **Recomendações:** Sugira os próximos passos para uma investigação mais aprofundada (ex: verificar logs de firewall, procurar o IP em feeds de ameaças, etc.).
    6.  Seu foco é identificar potenciais riscos e comportamentos maliciosos associados ao filehash analisado.

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
    ...(Listas na tabela os achados de todas as fontes analisadas)

    Existem fortes evidências de que este filehash está ou esteve envolvido em operações maliciosas: (**Se não existir comportamento malicioso, ignorar essa parte e não construir**) 

    *   **Associação a Campanhas de Phishing**: O Urlscan desecreve como um domínio de phishing que se disfarça como um portal de serviço governamental para regularização de documento, com últiplos scans públicos para URLs como `https://portalbrofcbenef.com/site-receita/consulta.html?cpf=... associados a ele.
    *   **Atividade de C2**: Infraestrutura distribuída e heterogênea, comum em operações de ataque para aumentar a resiliência e evitar bloqueios.

    **Táticas/Procedimentos (ATT&CK) observados nos pulsos associados**  

    - **T1071 – Application Layer Protocol (HTTP/DNS)** – uso de domínios legítimos como capa.  
    - **T1045 – Software Packing** – arquivos UPX, ofuscados.  
    - **T1027 – Obfuscated Files or Information** – presença de scripts/payloads ofuscados.  
    - **T1105 – Ingress Tool Transfer** – entrega de arquivos maliciosos via HTTP/HTTPS.  
    - **T1192 – Spearphishing Link** – links de phishing apontando para `example.com`.  
    - **T1095 – Non‑Application Layer Protocol** – uso de DNS para C2.  
    - **T1486 – Data Encrypted for Impact** – ransomware associado em alguns pulsos.  

    ---

    ## 3. Informações de Campanha Associada
    | Campo | Valor |
    |-------|-------|
    | **Nome de Arquivos** | atualize_outlook.js |
    | **Tipo** | script, js |
    | **Obfuscação** | XOR em variáveis de carregamento |
    | **Classe** | Infostealer |
    | **Grupo/Família** | Mirai |
    | **Alvo** | Usuários de emails do outlook, etc. |
    | **Localização** | Brasil |
    | **Objetivos** | Extração de dados de autenticação e PII |

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

    return prompt
