# Relatório de Threat Intelligence – IP **3.33.130.190**

> **Fonte dos dados**: Shodan, IPInfo.io, WHOIS / RDAP, URLScan.io, VirusTotal, AbuseIPDB, pesquisa manual.  
> **Última coleta Shodan**: 2025‑11‑25 14:15 UTC.  

---

## 1. Resumo Executivo
O endereço **3.33.130.190** pertence à infraestrutura de nuvem da **Amazon (AWS Global Accelerator)**, localizado em **Seattle, WA, EUA** (ASN AS16509 – Amazon Technologies Inc.).  Ele expõe somente as portas **80 (HTTP)** e **443 (HTTPS)** e está associado a dezenas de domínios que apresentam *landings* de campanhas publicitárias e, em vários casos, são marcados como **phishing** ou **maliciosos** por diferentes mecanismos (VT, AbuseIPDB, crowdsourced intel).  O IP tem **abuse confidence score 29** (AbuseIPDB) e **reputação negativa –72** (VirusTotal), com múltiplas alegações de uso para hospedagem de URLs de phishing, bem como detecção de atividade suspeita por feeds de inteligência (e.g., “Phishing URL Finding | urlabuse.com”).  Não há indícios claros de funcionamento como servidor C2 ou botnet, mas a grande rotatividade de domínios sugere um padrão de *fast‑flux* / *phishing‑as‑a‑service*.

---

## 2. Análise de Comportamento
| Evidência | Interpretação |
|-----------|---------------|
| **Hostnames**: `a2aa9ff50de748dbe.awsglobalaccelerator.com`, `ottawacatholicschools.org` | IP usado como ponto de aceleração de tráfego para múltiplos domínios, inclusive um domínio legítimo (`ottawacatholicschools.org`) possivelmente comprometido ou usado indevidamente. |
| **Tags Shodan**: `cloud` | Confirma que o serviço está sendo oferecido a partir de infraestrutura de nuvem pública. |
| **Portas abertas**: 80/tcp, 443/tcp | Servidor web padrão – típico de hosts que servem páginas de captura/landings. |
| **Resultado do URLScan.io**: 100+ submissões mostrando domínios variados (ex.: `lucapizza.uk`, `tjfincancial.com`, `cronuxcapital.com`, `fintechcy.com`, etc.) todas apontando ao mesmo IP; várias têm *age* de dias a poucos meses, indicando criação recente para campanhas. | Indica uso de “parking” ou “landing” de tráfego, típico de esquemas de phishing ou de monetização de tráfego mal‑intencionado. |
| **VirusTotal**: 2 malicious, 2 suspicious, 60 harmless; reputação -72; tag “Phishing URL Finding”. | Confirma que parte das URLs hospedadas são reconhecidas como phishing. |
| **AbuseIPDB**: 20 relatórios, 16 usuários distintos, confidence 29. | Comunidade reporta abuso, embora o score não seja extremamente alto, demonstra atividade suspeita recorrente. |
| **Crowdsourced context (ArcSight)**: “Phishing URL Finding”. | Refirma que o IP está sendo usado para hospedar URLs de phishing. |
| **Ausência de outras portas (ex.: 22, 23, 3389, 445, 53)** | Não há indícios de que o host ofereça serviços típicos de C2, SSH, ou DNS mal‑configurado. |

**Conclusão:** O endereço se comporta como **servidor web de hospedagem de landing pages mal‑intencionadas**, possivelmente controlado por atores que utilizam infraestrutura AWS para **gerar tráfego de phishing ou cloaking**. Não há evidência de botnet ou servidor de comando‑e‑controle, mas o padrão de múltiplos domínios efêmeros reflete técnicas de *fast‑flux*.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços Detectados
| Porta | Protocolo | Serviço | Comentário |
|-------|-----------|---------|------------|
| 80    | TCP       | HTTP    | Responde com um pequeno documento HTML (114 bytes) – simples página de teste/landed. |
| 443   | TCP       | HTTPS   | SSL/TLS com certificado da **GoDaddy** (CN = `ottawacatholicschools.org`). O certificado vigora até **2026‑05‑28**. |

> Não foram identificadas vulnerabilidades (CVEs) associadas diretamente a esses serviços nos dados Shodan disponíveis. Caso o host execute algum *web‑app* (CMS, frameworks), recomenda‑se inspeção de banners e cabeçalhos HTTP para detectar versões vulneráveis.

### 3.2 Vulnerabilidades (CVEs) Identificadas
- **Nenhum CVE explícito** foi retornado pelos scans Shodan ou pelos relatórios VT.  
- **Risco potencial:** Se o servidor web estiver rodando softwares não‑atualizados (ex.: Apache, Nginx, PHP, WordPress etc.), vulnerabilidades conhecidas poderiam ser exploradas para *defacement* ou *drive‑by*. Recomenda‑se análise de *fingerprinting* adicional.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS16509 – Amazon Technologies Inc.** |
| **ISP** | **Amazon.com, Inc.** |
| **Organização** | Amazon Technologies Inc. |
| **País** | United States (US) |
| **Região/Estado** | Washington |
| **Cidade** | Seattle |
| **Latitude/Longitude** | 47.6339 / ‑122.3476 |
| **Tipo de uso** (AbuseIPDB) | Content Delivery Network (CDN) |
| **Domínios associados** | `a2aa9ff50de748dbe.awsglobalaccelerator.com`, `ottawacatholicschools.org`, e mais de 100 domínios analisados via URLScan.io. |

---

## 5. Recomendações (Próximos Passos)

1. **Correlacionar logs de rede** – Verificar nos firewalls e sistemas de deteção (IDS/IPS) todo o tráfego de entrada/saída para 3.33.130.190:80/443. Identificar fontes internas que tenham se comunicado com esse IP e analisar padrões de requisição (user‑agent, URI, volume).  
2. **Enriquecimento de IOC** – Inserir o IP e os domínios associados em soluções de bloqueio de URL e listas de bloqueio de reputação (e.g., Cisco Umbrella, FortiGuard). Consultar feeds de Threat Intelligence (OTX, Abuse.ch, PhishTank) para atualizações.  
3. **Análise de conteúdo** – Baixar e analisar as páginas hospedadas (via sandbox) para detectar scripts maliciosos, redirecionamentos ou coleta de credenciais.  
4. **Verificar mensagens de e‑mail** – Caso a sua organização receba e‑mails contendo links para esses domínios, marcar como phishing e remover de campanhas.  
5. **Monitoramento contínuo** – Configurar monitoramento via Shodan/Passive DNS para detectar novas associações de domínio ao mesmo IP ou mudanças de **ASN**.  
6. **Notificação ao provedor** – Considerar abrir um ticket na AWS Abuse (via <https://aws.amazon.com/report-abuse/>) informando os domínios/phishing identificados para possível remoção conforme a política de uso aceitável da Amazon.  
7. **Avaliar bloqueio seletivo** – Se o tráfego ao IP for estritamente indesejado, aplicar bloqueio de camada 3/4 (IP/port) reduzindo o risco de exfiltração ou acesso a conteúdos de phishing.

---

## 6. Observações Finais
- O IP **não apresenta tráfego típico de C2**, mas a sua utilização como ponto de entrega de landing pages de phishing torna‑o um **risco relevante** para usuários que recebem e‑mails contendo URLs curtas ou redirecionamentos.  
- A presença de um certificado **válido** para `ottawacatholicschools.org` indica que domínios legítimos podem ser **abuso de confiança** ao apontar para a mesma infraestrutura.  
- A prática de **apontar múltiplos domínios recém‑criados** a um mesmo endereço de aceleração (Global Accelerator) evidencia o uso de recursos de nuvem como *infrastructure‑as‑a‑service* para distribuir rapidamente campanhas de phishing.  

Este relatório deve ser usado como base para **detecção, resposta e mitigação** de ameaças associadas ao IP 3.33.130.190 dentro do seu ambiente organizacional.