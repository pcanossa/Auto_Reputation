# Relatório de Threat Intelligence – IP **15.197.148.33**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io, VirusTotal.  
> **Última coleta Shodan**: 2025‑11‑25  

## 1. Resumo Executivo
O endereço **15.197.148.33** pertence à Amazon Web Services (AWS) – serviço Global Accelerator – e está alocado em **Seattle, WA, EUA** (ASN AS16509, ISP Amazon.com, Inc.). São encontradas **portas 80 (HTTP) e 443 (HTTPS)** com um certificado TLS emitido pela GoDaddy para o domínio **bngindia.com**. O IP aparece como ponto de destino de centenas de domínios diferentes (principalmente landing pages de campanhas de marketing/ads) e já foi rotulado como “malicious” por um fornecedor de inteligência (Criminal IP) no VirusTotal, apresentando reputação ‑16. Não há vulnerabilidades CVE explicitamente divulgadas pelo Shodan, mas o volume alto de domínios, a presença de tags de phishing e o histórico de uso como redirector sugerem que pode estar sendo utilizado como **infraestrutura de ataque ou de phishing**.

---

## 2. Análise de Comportamento
| Evidência | Descrição |
|-----------|-----------|
| **Tag Shodan “cloud”** | Indica que o endereço faz parte de um provedor de nuvem (AWS). |
| **Global Accelerator (awsglobalaccelerator.com)** | Serviço da AWS usado para otimizar tráfego e mascarar a origem real dos servidores. |
| **Múltiplos domínios apontando para o IP** (ex.: `sallysapizzadelivery.com`, `vtcnet.app`, `quikkat.com`, `bngindia.com`, entre centenas listados no URLScan) | Característica típica de “**droplet**” ou **fast‑flux** usado para distribuir carga ou redirecionar tráfego malicioso. |
| **Tags “@phish_report” em alguns URLs** (`pexcard.info`, `keepourcountryclean.com`) | Indica que o IP já esteve associado a campanhas de phishing que foram reportadas. |
| **Resultado VirusTotal – “malicious” (Criminal IP)** | Um motor de reputação detectou atividade maliciosa (possivelmente como parte de botnet ou serviço de comando/controle). |
| **Nenhum banner de serviço vulnerável (ex.: Apache, OpenSSH, etc.)** | Não há indícios de vulnerabilidades conhecidas do serviço HTTP/HTTPS expostas. |
| **Alta taxa de novos “lander” ou “landing page”** (URLs com caminho `/lander`) | Padrão típico de tráfego de afiliados, mas também usado em campanhas de phishing ou entrega de malware. |

**Conclusão comportamental:** o IP atua como ponto de concentração de tráfego web (HTTP/HTTPS) para um grande número de domínios, alguns já marcados como phishing. Embora a infraestrutura seja legítima (AWS), o padrão de uso (múltiplos domínios, tags de phishing, reputação negativa) sugere que o endereço pode estar sendo **abuso** como:

* **Servidor de redirecionamento** para campanhas de phishing ou de malware.  
* **Possível “C2”** (comando e controle) de bots que utilizam HTTP/HTTPS como canal de comunicação.  
* **Serviço de “proxy” ou “fast‑flux”** para ocultar a origem real de ataques.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços Detectados
| Porta | Protocolo | Serviço | Observações |
|-------|-----------|---------|--------------|
| **80** | TCP | HTTP | Responde com `200 OK`, conteúdo HTML vazio (114 bytes). |
| **443** | TCP | HTTPS | Certificado TLS (GoDaddy) para **bngindia.com**; suporte a TLS 1.2/1.3. |

Não foram identificados outros serviços (ex.: SSH, RDP, SMTP) no scan atual.

### 3.2 Vulnerabilidades (CVEs) Identificadas pelo Shodan
- **Nenhuma vulnerabilidade CVE** reportada diretamente nos banners de serviço (HTTP/HTTPS).  
- **Observação:** o fato de o IP hospedar milhares de domínios pode ser explorado por atacantes para alavancar técnicas de **domain‑fronting**, **fast‑flux** ou **credential stuffing** contra aplicações web que utilizam este endereço como backend.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS16509 – Amazon Technologies Inc.** |
| **ISP** | Amazon.com, Inc. |
| **Organização** | Amazon Technologies Inc. |
| **País** | United States (EUA) |
| **Estado / Região** | Washington |
| **Cidade** | Seattle |
| **Latitude / Longitude** | 47.6339, ‑122.3476 |
| **Anycast** | Sim (anycast = true) |
| **Tipo de rede** | Direct Allocation (15.196.0.0/14) |

---

## 5. Recomendações (próximos passos)

1. **Correlacionar logs internos** – Verificar firewalls, proxies e sensores IDS/IPS para conexões HTTP/HTTPS ao IP 15.197.148.33, especialmente em horários de pico de tráfego das suas aplicações.  
2. **Enriquecer com feeds de ameaças** – Consultar fontes como Spamhaus, AbuseIPDB, OTX, AlienVault OTX e outros para confirmar se há listagens adicionais.  
3. **Bloqueio seletivo** – Caso haja evidência de que seu tráfego legítimo nunca deve alcançar esse IP, considere bloqueá‑lo na camada de perímetro (firewall ou filtro de URL).  
4. **Análise de domínios associados** – Extrair a lista completa de domínios que resolvem para esse IP (consultar DNS records ou o endpoint `/dns` do Shodan) e validar se algum deles está em sua lista de permissões.  
5. **Monitoramento contínuo** – Configurar alertas no Shodan (e/ou no VirusTotal) para mudanças de status (ex.: nova tag “malicious”, novos serviços).  
6. **Reportar abuso ao responsável** – Caso a atividade seja confirmada como maliciosa, abrir ticket de abuso com **trustandsafety@support.aws.com** (contato de abuso da AWS) incluindo detalhes de logs, timestamps e amostras de tráfego.  
7. **Análise de certificados TLS** – Verificar se o certificado apresentado corresponde ao domínio que seu cliente espera; discrepâncias podem indicar ataques de **man‑in‑the‑middle** ou de **domain‑fronting**.  
8. **Investigação de possíveis C2** – Caso suspeite de comunicação de botnet, capturar amostras de tráfego HTTP/HTTPS para análise de cabeçalhos, parâmetros e payloads (ex.: comandos codificados em URL ou body).  

---

## 6. Considerações Finais
Embora o IP pertença a uma infraestrutura de nuvem legítima (AWS Global Accelerator), a **concentração de domínios de baixa reputação**, **tags de phishing** e a **detecção como “malicious”** por um provedor de reputação sugerem que ele está sendo **abuso** como ponto de entrega/redirecionamento para campanhas de phishing ou possivelmente como **canal de comando e controle** para botnets que utilizam tráfego web padrão. A recomendação principal é **monitorar e, quando necessário, bloquear** o tráfego para esse endereço, além de **reportar o abuso** aos responsáveis da AWS e atualizar seus feeds de inteligência para evitar futuros incidentes.