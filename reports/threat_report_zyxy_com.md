# Relatório de Threat Intelligence – Domínio **zyxy.com**

> **Fonte dos dados**: WHOIS (enom.com), VirusTotal (API v3), URLScan.io, AlienVault OTX, DNS (public resolver), DNSDumpster, Phishing Army blocklist, cURL, Certificados Let’s Encrypt.  
> **Timestamp da Análise**: 2026-01-29T15:33:09.892236.  

---  

## 1. Resumo Executivo
O domínio **zyxy.com** foi registrado em 2001 via eNom (registrador / registrar ID 48) e utiliza os servidores de nomes **ns1.gocheapweb.com** e **ns2.gocheapweb.com** (OVH – França). O único registro DNS público resolve‑se para **167.99.19.99**, endereço pertencente ao provedor de cloud **DigitalOcean** (ASN 14061 – The Netherlands).  

O **VirusTotal** indica **15 deteções maliciosas** e **1 suspeita** (de 44 avaliações), com a maioria dos antivírus classificando o domínio como **phishing** ou **malware**. O domínio também aparece em múltiplas fontes de inteligência de ameaças (AlienVault OTX, Phishing Army, diversas listas de bloqueio) e tem certificados TLS válidos emitidos pela **Let’s Encrypt**, mas isso não impede seu uso maléfico.  

Em suma, **zyxy.com** apresenta forte indicação de ser parte de infraestrutura de **phishing** e possivelmente de **distribuição de malware**, sendo adequado ser incluído em listas de bloqueio e monitorado ativamente.  

---  

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|--------------|
| **VirusTotal** (última análise) | 15 malicious, 1 suspicious, 27 undetected, 50 harmless. Engines como **BitDefender, Fortinet, G‑Data, Sophos, Webroot** marcam como **phishing**; **VIPRE** e **SOCRadar** marcam como **malware**. | Alta taxa de detecção indica uso ativo em campanhas de phishing/malware. |
| **AlienVault OTX – Pulse** | Incluído na lista *CERT.PL list of malicious domains* (público, TLP white). | Domínio reconhecido por autoridades nacionais como malicioso. |
| **Phishing Army blocklist** | Presente na lista de bloqueio de phishing no momento da verificação. | Confirmação adicional de uso como vetor de phishing. |
| **URLScan.io** (2 execuções) | Resoluções para **167.99.19.99**, tráfego HTTP/HTTPS observados, sem resposta (conexão reset). | Infraestrutura provavelmente configurada para servir como redirecionamento ou “dropper” de carga maliciosa. |
| **cURL** | Conexão ao IP é imediatamente resetada. | Possível mecanismo de defesa (Web‑Application‑Firewall) ou servidor configurado para bloquear acessos não‑legítimos. |
| **Certificados TLS** | Let’s Encrypt emitindo certificados válidos (vários períodos). | Adoção de TLS legítimo para evitar bloqueios baseados em ausência de HTTPS; prática comum em grupos de crime. |
| **DNSDumpster** | IP aponta para DigitalOcean (NL), banners HTTP → redirecionamento para **https://167.99.19.99/**, HTTPS apresenta certificado “TRAEFIK DEFAULT CERT”. | Servidor possivelmente rodando **Traefik** como proxy reverso, típico de ambientes de “C2‑as‑a‑Service”. |
| **SPF TXT Record** | `v=spf1 +a +mx +ip4:51.195.105.137 ~all` | Configuração de e‑mail “soft‑fail”; indica presença de infraestrutura de e‑mail (possível spoofing). |

**Táticas/Procedimentos (MITRE ATT&CK) observados**  

| Tática | Técnica | Comentário |
|--------|---------|------------|
| **Reconhecimento** | T1087 – **Account Discovery** (uso de domínios para lookup de e‑mail). |
| **Comando & Controle** | T1071 – **Application Layer Protocol** (HTTP/HTTPS via Traefik). |
| **Distribuição** | T1105 – **Ingress Tool Transfer** (possível entrega de payloads). |
| **Phishing** | T1566 – **Phishing** (domínio listado como phishing). |
| **Obfuscação** | T1027 – **Obfuscated Files or Information** (certificados legítimos para mascarar). |
| **Serviço de C2** | T1095 – **Non‑Application Layer Protocol** (possível uso de DNS TXT/SPF). |

---  

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|------|-------|
| **ASN** | **14061 – DIGITALOCEAN‑ASN** (bloco 167.99.16.0/22). |
| **ISP / Provedor** | **DigitalOcean**, datacenter localizado em **The Netherlands** (país de registro da IP). |
| **Nome do Registrador** | **eNom, Inc.** (IANA ID 48). |
| **Nameservers** | `ns1.gocheapweb.com` (OVH‑FR), `ns2.gocheapweb.com` (OVH‑FR). |
| **Localização da IP** | País: **Holanda (Netherlands)** – Cidade: **Amsterdam‑area** (geo‑IP padrão). |
| **Endereço IPv4** | **167.99.19.99** (único A‑record). |
| **IPv6** | Não registrado. |
| **DNSSEC** | **Não assinado**. |
| **Certificado TLS** | Let’s Encrypt (CN = zyxy.com), validade até **2026‑01‑11**. |
| **SPF** | `v=spf1 +a +mx +ip4:51.195.105.137 ~all`. |

---  

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio Principal** | `zyxy.com` | Analisado. |
| **Nameservers** | `ns1.gocheapweb.com`, `ns2.gocheapweb.com` | Ambos apontam para OVH (FR). |
| **IP Resolvido** | `167.99.19.99` | DigitalOcean (NL), usado em URLScan.io e DNSDumpster. |
| **IP de Nameserver** | `141.95.70.51` (ns1.gocheapweb.com – OVH FR), `51.38.120.11` (ns2.gocheapweb.com – OVH FR). |
| **IP de SPF** | `51.195.105.137` (referenciado no TXT). |
| **Domínios associados em feeds OTX** | *Nenhum domínio adicional explícito*, porém o pulse agrupa mais de **129 k** de indicadores de hostname. |
| **Outros indicadores de reputação** | Listas de phishing (Phishing Army), múltiplas detecções de antivírus, presença em bases de dados de ameaças (Forcepoint, Sophos, etc.). |

---  

## 5. Recomendações de Investigação
1. **Bloqueio imediato** do domínio `zyxy.com` e do IP `167.99.19.99` em firewalls, proxies web e filtros DNS internos.  
2. **Monitoramento de logs de DNS** para detectar consultas internas ao domínio ou aos seus nameservers (`gocheapweb.com`).  
3. **Análise de tráfego**: correlacione fluxos de saída para `167.99.19.99` ou para os nameservers OVH na sua rede; procure por padrões de **HTTPS POST** a caminhos desconhecidos.  
4. **Verificar e‑mail**: procure por mensagens enviadas com o endereço `@zyxy.com` como remetente ou Reply‑To; a presença do registro SPF indica tentativa de spoofing.  
5. **Enriquecimento adicional**: consultar feeds como **Passive DNS**, **Shodan**, **Censys** e **IP‑Intelligence** para confirmar outros serviços (ex.: servidores SSH, bancos de dados) rodando no IP.  
6. **Threat Hunting**: buscar hashes de arquivos associados a campanhas de phishing que referenciam `zyxy.com` (ex.: arquivos .html, documentos Word com links).  
7. **Atualização de listas de bloqueio**: inserir o domínio e IP em soluções de *Threat Intelligence Platform* (TIP) internas e compartilhar com parceiros (ISACs) para mitigação coletiva.  
8. **Analisar o certificado TLS**: verificar se o certificado está sendo usado em outros domínios (possível **wildcard**).  

---  

## 6. Conclusão
Embora o domínio `zyxy.com` possua um certificado TLS válido e esteja alocado em um provedor de cloud respeitável, a **concentração de detecções maliciosas** (phishing e malware) em múltiplas plataformas de inteligência, aliada à presença em listas de bloqueio oficiais, indica que ele **é amplamente utilizado como vetor de ataque**. Não há indícios de comprometimento interno direto, mas o risco de **redirecionamento de usuários** e **entrega de payloads** é alto. Recomenda‑se tratá‑lo como **alto risco**, bloqueando e monitorando continuamente quaisquer indicadores relacionados.