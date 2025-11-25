# Relatório de Threat Intelligence – Domínio **stelarbroker.com**

> **Fonte dos dados**: WHOIS (whois.godaddy.com), VirusTotal (API v3), AlienVault OTX, Urlscan.io (sem resultados).  
> **Última coleta VirusTotal**: 2025‑12‑24 (timestamp 1761373403).

---

## RESUMO EXECUTIVO
O domínio **stelarbroker.com** foi registrado em 11 / 09/2025 via GoDaddy (registrante oculto por “Domains By Proxy”). Todos os registros DNS apontam para a rede da **Cloudflare** (nameservers *KINSLEY.NS.CLOUDFLARE.COM* e *ROMMY.NS.CLOUDFLARE.COM*; IPs A 172.67.146.94 e 104.21.55.89, IPv6 2606:4700:3036::ac43:925e e 2606:4700:3036::6815:3759).  

No VirusTotal, 1 engine (CRDF) classificou o domínio como **malicious** e duas ferramentas (Bfore.Ai PreCrime, Gridinsoft) marcaram como **suspicious**; o restante das 93 análises relata “harmless” ou “undetected”. Não há indicações de utilização em campanhas de phishing ou de C2 em outras fontes (AlienVault OTX não apresenta pulsos, urlscan.io não retornou scans).  

Em suma, o domínio apresenta sinais tímidos de **atividade potencialmente maliciosa**, porém o perfil de rede (Cloudflare) e a ausência de reputação consolidada sugerem que ainda pode estar em fase inicial ou ser usado em conjunto com infraestruturas de terceiros.

---

## ANÁLISE DE COMPORTAMENTO
| Indicador | Observação |
|-----------|------------|
| **Whois** | Registro privado (Domain Privacy), data de criação recente (11‑09‑2025) e expiração em 11‑09‑2026. |
| **DNS** | Resolução para serviços da Cloudflare (CDN/Anycast). Não há registros de MX, TXT ou CNAME que apontem para infraestrutura de e‑mail ou outros serviços suspeitos. |
| **JARM** | `27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c` – padrão típico de servidores Cloudflare, não indica customização de TLS. |
| **Detecção VT** | 1/93 “malicious” (CRDF), 2 “suspicious” (Bfore.Ai PreCrime, Gridinsoft), 61 “harmless”, 31 “undetected”. A presença de uma única marcação “malicious” pode derivar de associação com listas de IPs/hosts já comprometidos ou de um false‑positive. |
| **Histórico de malware / botnet** | Nenhum registro de associação direta a botnets, C2 ou campanhas de phishing nas bases consultadas (AlienVault, urlscan.io). |
| **Certificado TLS** | Emitido por *Google Trust Services* (validade 15‑09‑2025 → 14‑12‑2025). Sem SANs suspeitos, apenas o próprio domínio e wildcard. |
| **Atividade pública** | Não há dados de tráfego (rank de popularidade vazio), nem menções em feeds de URL‑haus ou PhishTank. |

**Conclusão comportamental:** O domínio exibe poucos indicadores de atividade maliciosa, mas a marcação “malicious” de um fornecedor de inteligência e duas avaliações “suspicious” sugerem que ele pode estar sendo testado ou utilizado em campanhas de baixo volume (ex.: download de payloads, landing pages temporárias). A presença de Cloudflare pode estar sendo usada para mascarar a origem real.

---

## INFORMAÇÕES DE REDE E GEOGRÁFICAS

| Campo | Valor |
|-------|-------|
| **ASN** | **AS13335 – Cloudflare, Inc.** |
| **ISP / Provedor** | **Cloudflare, Inc.** (serviço de reversão de DNS/DDoS protection) |
| **Endereços IP** | - 172.67.146.94 (A) <br> - 104.21.55.89 (A) <br> - 2606:4700:3036::ac43:925e (AAAA) <br> - 2606:4700:3036::6815:3759 (AAAA) |
| **Localização (anycast)** | Principalmente Estados‑Unidos (São Francisco / Los Angeles) – padrão anycast da Cloudflare, distribuído globalmente. |
| **Registros DNS** | NS: kinsley.ns.cloudflare.com, rommy.ns.cloudflare.com <br> SOA: kinsley.ns.cloudflare.com (serial 2383829061) |
| **Serviço de CDN** | Cloudflare (proteção DDoS, WAF, caching). |

---

## DOMÍNIOS E IPs RELACIONADOS
- **Domínios**: *Nenhum sub‑domínio ou domínio “sombra” encontrado nas consultas WHOIS/DNS.*  
- **IPs associados**: 172.67.146.94, 104.21.55.89 (IPv4); 2606:4700:3036::ac43:925e, 2606:4700:3036::6815:3759 (IPv6).  
- **Nameservers**: kinsley.ns.cloudflare.com, rommy.ns.cloudflare.com (também usados por milhares de outros domínios; monitorar por co‑ocorrência).  
- **Entidades**: Registrador – GoDaddy.com, LLC (IANA ID 146). Registrante – “Domains By Proxy, LLC” (privado).  

---

## RECOMENDAÇÕES DE INVESTIGAÇÃO
1. **Correlacionar logs internos** – Verificar se algum cliente ou servidor interno já fez requisições DNS ou HTTP/HTTPS para `stelarbroker.com` ou para os IPs da Cloudflare listados.  
2. **Passive DNS** – Consultar fontes de passive DNS (e.g., PassiveTotal, SecurityTrails) para histórico de resolução do domínio e identificar eventuais mudanças de IP ou de nameserver que indiquem *fast‑flux* ou uso temporário.  
3. **Feeds de Inteligência** – Incluir os IPs 172.67.146.94 e 104.21.55.89 em buscas nos principais feeds (AbuseIPDB, OTX, MISP, VirusTotal IP lookup) para detectar novas marcações “malicious”.  
4. **Análise de URLs** – Caso existam URLs públicas apontando para `stelarbroker.com`, submeter a sandboxes (Cuckoo, Hybrid Analysis) para observar eventual entrega de payloads.  
5. **Monitoramento de Certificado** – Acompanhar a validade e renovação do certificado TLS; mudanças súbitas no CN ou nas extensões podem indicar “domain flux”.  
6. **Threat Hunting** – Criar regras de detecção (SIEM) para tráfego HTTP(S) com o *User‑Agent* “Cloudflare‑Ray” combinado a consultas DNS para o domínio, de modo a captar possíveis comunicações de C2 ocultas por HTTPS.  
7. **Reporting externo** – Caso novas evidências de comprometimento sejam encontradas, abrir ticket nas plataformas de reporte (e.g., VirusTotal, AbuseIPDB) com os indicadores coletados.  

--- 

*Este relatório tem como objetivo identificar riscos e comportamentos suspeitos associados ao domínio `stelarbroker.com`. Não contém recomendações de mitigação de vulnerabilidades específicas ao seu ambiente.*