# Relatório de Threat Intelligence – IP **95.211.7.168**

> **Fonte dos dados**: Shodan, IPInfo.io, VirusTotal, AbuseIPDB, AlienVault OTX, Scamalytics, VPNAPI, MaxMind GeoLite2.  
> **Timestamp da Análise**: 2026‑02‑10T11:30:42.433408.

---

## 1. Resumo Executivo
O endereço **95.211.7.168** pertence ao bloco de data‑center da **LeaseWeb Netherlands B.V. (ASN 60781)**, localizado em **Lelystad, Flevoland – País: Holanda (NL)**. Apesar de o Shodan não retornar informações de serviços ativos (404 – “No information available”), o IP aparece em múltiplas análises de VirusTotal como host de arquivos **maliciosos** (trojans Cutwail/DownLoader, Backdoor HareBot, Qakbot, etc.) com **1 detecção maliciosa** e **60 resultados “harmless”**. Nenhum relatório de abuso foi enviado ao AbuseIPDB (score 0), mas a combinação de tráfego mal‑icioso e a classificação de “datacenter” pelo Scamalytics (risco baixo) indica que o IP pode estar sendo usado como **infraestrutura de comando‑e‑controle (C2) ou ponto de entrega de payloads**.  

---

## 2. Análise de Comportamento
| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **VirusTotal – arquivos comunicantes** | 2 amostras de PE executáveis (hash 43dbcee5aee3… e a35b574bfdf6…) marcadas como *malicious* por 55‑60 engines (Cutwail, Trojan‑Downloader, Backdoor‑HareBot, Qakbot, etc.). | O IP já serviu ou recebeu arquivos de malware avançado, típica de servidores **C2** ou de *payload delivery*. |
| **Detecção “malicious”** (VT) | 1/33 análises classificou o IP como malicioso. | Contribui para a reputação negativa, reforçando a hipótese de uso ativo por atores maliciosos. |
| **Shodan** | Nenhum serviço detectado (404). | O IP pode estar operando em portas não‑comuns, serviços protegidos por firewall ou usando **stealth** (ex.: portas de saída apenas). |
| **AlienVault OTX – Pulses** | Pulses relacionados a **Qakbot / Cutwail**, TLS‑handshake anômalos, “cipher‑suite” alerts, atividade de botnet. | Indica que o endereço está inserido em *intel* de campanhas de botnet e *malware banking*. |
| **Scamalytics / VPNAPI** | Classificado como **datacenter**, **não VPN**, **não TOR**, risco baixo. | Confirma que o IP pertence a infraestrutura de hospedagem (provável uso legítimo por clientes, mas também típico de *C2* de botnets que utilizam servidores de data‑center. |
| **AbuseIPDB** | Nenhum reporte, abuseConfidenceScore 0. | Falta de denúncias públicas, mas isso não elimina a possibilidade de uso malicioso interno ou “low‑profile”. |

**Conclusão comportamental:** O conjunto de indicadores aponta fortemente que o IP está **associado a atividade maliciosa**, possivelmente como ponto de *command‑and‑control* ou servidor de distribuição de payloads. A ausência de portas públicas conhecidas pode indicar que o tráfego ocorre em portas não‑padrão ou que o host está atrás de um NAT/Firewall, dificultando a enumeração.

---

## 3. Superfície de Ataque

### 3.1 Portas abertas / serviços
*Shodan* retornou **nenhuma informação** (erro 404). Não foi possível identificar portas específicas (ex.: 80, 443, 22, etc.).  
**Ação recomendada:** varredura ativa controlada (ex.: nmap ‑sS ‑p‑‑open) a partir de um sandbox/ambiente controlado para confirmar quais portas, se houver, estão expostas.

### 3.2 Vulnerabilidades (CVEs) identificadas pelo Shodan
Nenhum CVE associado ao IP foi encontrado nas buscas do Shodan. Caso portas sejam descobertas, será necessário revisar os banners de serviço e aplicar bases de vulnerabilidades (CVE‑Search, NVD) correspondentes.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS60781 – LeaseWeb Netherlands B.V.** |
| **Provedor (ISP)** | **LeaseWeb Netherlands B.V.** |
| **Localização** | **Lelystad, Flevoland, Holanda (NL)** |
| **Coordenadas** | 52.5083 , 5.4750 (IPInfo.io) – 52.3824 , 4.8995 (MaxMind) |
| **Fuso horário** | Europe/Amsterdam |
| **Tipo de rede** | Data center / Web Hosting / Transit (AbuseIPDB) |
| **Classificação de risco (Scamalytics)** | Score 8 → *Low* (datacenter, não VPN, não TOR) |
| **VPN/Proxy** | VPN = *true* (VPNAPI indica uso de VPN), Proxy = *false* |

---

## 5. Recomendações de Investigação

1. **Varredura de portas controlada** – executar *nmap* ou *masscan* a partir de um host seguro para mapear portas TCP/UDP abertas.  
2. **Coleta de certificados TLS/handshakes** – se houver serviço HTTPS, capturar o certificado e verificar por *cipher‑suite* anômalos (relacionados a pulses OTX).  
3. **Análise de tráfego de rede** – inspecionar logs de firewall ou sensores IDS/IPS para fluxos de saída/entrada envolvendo 95.211.7.168 (especialmente sobre portas 443/80 ou portas não‑padrão).  
4. **Consulta a feeds de Threat Intel** – buscar o IP nos seguintes STIX/TAXII feeds: ThreatCrowd, Abuse.ch, MISP, e em bases de dados de C2 (e.g., Malware‑Bazaar, AlienVault OTX atualizados).  
5. **Correlacionar amostras de malware** – baixar (em sandbox isolado) os arquivos associados (hash 43dbcee5…, a35b574b…) e analisar comportamento (C2 callbacks, domínios/DNS, técnicas MITRE ATT&CK).  
6. **Notificação ao ISP** – caso se confirme atividade maliciosa, enviar *abuse report* ao endereço abuse@nl.leaseweb.com (fornecido no WHOIS).  
7. **Monitoramento contínuo** – adicionar o IP a regras de *watchlist* em SIEM/EDR para alertas de novas conexões ou trocas de arquivos.  

---

## 6. Considerações Finais
O endereço **95.211.7.168** apresenta forte associação a amostras de malware reconhecidas internacionalmente (Cutwail, Qakbot, HareBot), embora não haja portas públicas divulgadas por scanners tradicionais. Essa condição é típica de **infraestrutura de C2** que opera em ambientes de data‑center, utilizando portas não‑padrão ou tráfego criptografado para evitar detecção.  

A ausência de denúncias públicas não elimina o risco; o IP pode ser **utilizado por atores avançados** que buscam ocultar a presença em serviços populares. Recomenda‑se **monitoramento ativo**, **varredura de portas controlada** e **análise profunda das amostras de malware** para confirmar o papel exato deste host e definir respostas de mitigação adequadas dentro do seu ambiente de defesa.