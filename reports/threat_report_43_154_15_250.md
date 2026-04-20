# Relatório de Threat Intelligence – IP **43.154.15.250**

> **Fonte dos dados**: Shodan, Netlas, IPInfo.io, VirusTotal, AbuseIPDB, AlienVault OTX, Scamalytics, VPNAPI.io, WHOIS/RDAP.  
> **Timestamp da Análise**: 2026-04-20T10:34:07.815601.  

---  

## 1. Resumo Executivo  
O endereço **43.154.15.250** pertence ao provedor de nuvem **Tencent Cloud (ASN AS132203)**, localizado em **Hong Kong, China**. Serviços públicos são visíveis nas portas **80 (HTTP), 443 (HTTPS) e 21 (FTP)**, com servidores **nginx**, **Laravel** e **PHP** expostos. Diversas vulnerabilidades críticas são associadas a esses componentes (ex.: **CVE‑2023‑44487** – DoS em nginx, **CVE‑2021‑28254** – RCE em Laravel, múltiplos CVEs em PHP). A maioria das bases de reputação (AbuseIPDB, Scamalytics, OTX) classifica o IP como de risco baixo ou neutro, embora o VirusTotal registre **uma única detecção “suspicious”** (SOCRadar). A combinação de serviços expostos e vulnerabilidades conhecidas eleva o **risco de uso como vetor de ataque (C2, entrega de malware, phishing ou DDoS)** a **moderado‑alto**.  

---  

## 2. Análise de Comportamento  

| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **VirusTotal** | 56 engines: “harmless/clean”, 37 “undetected”, 1 “suspicious” (SOCRadar) | Predominância de resultados benignos, porém a presença de uma detecção “suspicious” indica que o IP já apareceu em alguma campanha ou como ponto de apoio. |
| **AlienVault OTX** | Reputação 0, **nenhum pulse** associado | Não há indicação de envolvimento em campanhas conhecidas, sugerindo que o IP ainda não foi amplamente utilizado por atores de ameaça. |
| **AbuseIPDB** | Abuse Confidence Score 0, nenhum relatório recente | Não há relatos de abuso confirmados por usuários finais. |
| **Scamalytics** | Score 0, risco “low”, não é proxy/VPN/TOR | Avaliação geral de baixo risco, porém a ferramenta não detecta atividades maliciosas ocultas. |
| **VPNAPI.io** | Flag `vpn: True` (indica que o IP pode ser usado como ponto de saída de VPN) | Possibilidade de ser utilizado para mascarar origens de tráfego, facilitando campanhas de phishing ou distribuição de malware. |
| **Netlas / Shodan (varredura de portas)** | Portas **21/tcp (FTP), 80/tcp (HTTP), 443/tcp (HTTPS)** abertas. Serviço **nginx** (versão vulnerável a CVE‑2023‑44487), **Laravel** (vulnerável a CVE‑2021‑28254) e **PHP** (vários CVEs 2024). | Exposição de serviços críticos com vulnerabilidades conhecidas, o que pode ser explorado por atacantes para **RCE, escalonamento de privilégio ou DDoS**. |
| **cURL / HTTP header** | Resposta HTTP 200 com cabeçalhos **Server: nginx**, **HSTS** habilitado, cookies Laravel (`XSRF‑TOKEN`, `laravel_session`). | Indica presença de aplicação web em produção, possivelmente vulnerável a ataques de **session hijacking** ou **CSRF** se configurada incorretamente. |
| **Passive DNS (Netlas)** | Hostnames associados: `mail-serve.hagro.cn`, `lxl.videof.com`, `develop.globalso.com`, `v6.globalso.com`, entre outros. | Diversidade de domínios aponta para uso de **hosting compartilhado** ou **fast‑flux**, prática comum em infraestruturas maliciosas. |

**Conclusão:** Embora a maioria das fontes de reputação classifique o IP como “low risk”, a presença de serviços públicos vulneráveis e a associação a múltiplos hostnames indicam que o endereço **pode ser aproveitado como ponto de apoio (C2, entrega de payloads ou phishing)**. A detecção “suspicious” no VT e a flag de VPN reforçam a possibilidade de uso malicioso oculta.

---  

## 3. Superfície de Ataque  

### 3.1 Portas abertas / Serviços  
| Porta | Serviço | Versão / Observação |
|-------|---------|----------------------|
| 21/tcp | FTP | Serviço aberto sem autenticação visível (potencial de *credential‑spraying*). |
| 80/tcp | HTTP | nginx – respostas 200, cabeçalhos `Server: nginx`, cookies Laravel, HSTS habilitado. |
| 443/tcp | HTTPS | nginx com certificado válido (Let’s Encrypt) para domínios como `lxl.videof.com`. |

> **Observação:** A exposição de FTP e web stack vulnerável aumenta a superfície de ataque, permitindo exploração remota sem necessidade de credenciais válidas.

### 3.2 Vulnerabilidades (CVEs) identificadas  
| Software | CVE | Gravidade (CVSS) | Impacto Potencial |
|----------|-----|------------------|-------------------|
| nginx | **CVE‑2023‑44487** | 7.5 (Alto) | DoS via HTTP/2 rapid reset; pode ser usado para interrupção de serviços. |
| Laravel | **CVE‑2021‑28254** | 8.8 (Crítico) | Deserialization RCE – permite execução de código arbitrário no servidor. |
| PHP | **CVE‑2024‑11235** (e variantes 11234‑11236, 8927) | 7‑9 (Alto‑Crítico) | Diversas falhas de buffer overflow, RCE e bypass de segurança. |
| FTP (protocolo genérico) | Nenhum CVE específico listado, mas serviço aberto é vetor para enumeração de usuários e brute‑force. |

> **Nota:** Como o software está exposto ao público Internet, exploits públicos já disponíveis podem ser utilizados contra o host.

---  

## 4. Informações de Rede e Geográficas  

| Campo | Valor |
|------|-------|
| **ASN** | **AS132203 – Tencent Net AP CN** |
| **ISP / Provedor** | **Tencent Cloud / Tencent Building, Kejizhongyi Avenue** |
| **Cidade / Região / País** | **Hong Kong, China** |
| **Latitude / Longitude** | **22.284 ° N / 114.176 ° E** (IPInfo) |
| **Faixa de IP** | **43.154.0.0/15** |
| **Tipo de rede** | Data‑center / Cloud Hosting (não VPN, não TOR) |
| **Contatos de Abuse** | `abuse@tencent.com`, `qcloud_net_duty@tencent.com` |

---  

## 5. Recomendações (Próximos Passos)

1. **Correlacionar logs internos** – Verificar firewalls, IDS/IPS e proxies para tráfego de/para **43.154.15.250** nas portas 21, 80 e 443. Atenção a tentativas de upload/download via FTP e solicitações HTTP suspeitas.  
2. **Monitoramento de indicadores** – Incluir o IP em watchlists de Shodan, VirusTotal Monitor, OTX e plataformas de inteligência interna (SIEM). Configurar alertas para novos *pulses* ou detecções “malicious”.  
3. **Varredura de vulnerabilidades** – Executar scans internos (ex.: Nessus, OpenVAS) focados nos serviços identificados, confirmando a versão exata do nginx, Laravel e PHP e aplicando patches imediatamente.  
4. **Análise de tráfego TLS/SSL** – Capturar e inspeccionar handshakes TLS (SNI, cipher suites) para detectar possíveis *malformed* handshakes ou uso de certificados auto‑assinados que indiquem C2.  
5. **Teste de alcance de portas** – Realizar varredura controlada (nmap –sS –p21,80,443) a partir de um host autorizado para confirmar a presença e comportamento dos serviços.  
6. **Bloqueio seletivo** – Caso a organização possua políticas de negação por região ou por provedores, considerar bloquear tráfego de saída/inbound para **AS132203** até que a avaliação de risco seja concluída.  
7. **Contato com o ISP** – Encaminhar evidências de vulnerabilidades e possíveis usos maliciosos ao abuse@tencent.com para que o provedor investigue e, se necessário, tome medidas de mitigação.  
8. **Revisar regras de firewall** – Garantir que o tráfego FTP seja restrito a IPs autorizados e que a exposição de HTTP/HTTPS esteja limitada a domínios conhecidos e certificados válidos.  

---  

## 6. Considerações Finais  
O IP **43.154.15.250** apresenta um cenário misto: **reputação geral baixa**, mas **exposição de serviços vulneráveis** que podem ser explorados por atores maliciosos. A combinação de um ambiente de cloud de grande porte (Tencent) e a possibilidade de uso de VPN eleva a probabilidade de que o endereço seja **utilizado como infraestrutura de apoio** – seja para **phishing, entrega de malware, C2 ou ataques DDoS**. Recomenda‑se **monitoramento ativo**, **correlação com logs internos** e **aplicação rápida de patches** nas vulnerabilidades identificadas. Caso ocorram indícios de atividade suspeita, a resposta deve envolver o **CSIRT interno**, o **provedor de cloud** e, se necessário, a **autoridade certificadora** para revogação de certificados comprometidos.  

---  

*Relatório gerado automaticamente por modelo de Threat Intelligence – 2026.*