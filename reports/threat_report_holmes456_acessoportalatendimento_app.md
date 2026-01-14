# Relatório de Threat Intelligence – Domínio **holmes456.acessoportalatendimento.app**

> **Fonte dos dados**: WHOIS (tucows.com), VirusTotal, URLScan.io, AlienVault OTX, consultas DNS públicas, cabeçalhos HTTP via cURL.  
> **Timestamp da Análise**: 2026-01-14T14:29:41.019162.  

---  

## 1. Resumo Executivo
O subdomínio **holmes456.acessoportalatendimento.app** foi registrado em 29/04/2025 no TLD *.app* por meio do registrador Tucows, com informações de contato ofuscadas. Ele resolve para dois endereços IPv4 ( 104.21.7.199 e 172.67.156.69 ) que pertencem à rede da Cloudflare (ASN 13335) e para dois endereços IPv6 da própria Cloudflare. O certificado TLS é emitido pela Google Trust Services (válido de 04/07/2025 a 02/10/2025) e cobre o domínio raiz e o curinga `*.acessoportalatendimento.app`.  

No VirusTotal o domínio apresenta **0 malicious**, **0 suspicious** e 93 “undetected”, ou seja, não há detecção por antivírus conhecidos. Não há pulsos no AlienVault OTX. As análises do URLScan.io mostram acesso via HTTP(S) nas portas 80 e 8443, retornando **403 Forbidden** por meio do CDN Cloudflare.  

Apesar da ausência de indicadores diretos de malware, o domínio apresenta **características típicas de infraestrutura utilizada por atores maliciosos**: registro recente, uso de subdomínio aleatório, hospedagem em CDN popular (facilita anonimato e rapidez de mudança), e ausência de informação de contato pública. Esses fatores, aliados à inexistência de reputação consolidada, indicam um **risco de uso como ponto de comando e controle (C2), phishing ou entrega de payloads**, especialmente se associado a outras campanhas de ameaças que utilizam sub‑domínios temporários em Cloudflare.

---  

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|----------------|
| **WHOIS** | Registrado em 2025, contato ofuscado, registrar Tucows | Domínio recém‑criado, possivelmente para uso temporário ou “throw‑away”. |
| **DNS** | A‑records: 104.21.7.199 / 172.67.156.69 <br> AAAA: 2606:4700:3032::6815:7c7 / 2606:4700:3034::ac43:9c45 | Endereços pertencentes à Cloudflare (AS13335). Anycast pode mascarar localização real. |
| **VirusTotal** | 0 malicious, 0 suspicious, 93 undetected, JARM 27d40d40d… | Nenhuma detecção por scanners, mas ausência de “malicious” não garante legitimidade. |
| **URLScan.io** | Várias execuções (HTTPS e HTTP) apontando para o mesmo IP; respostas HTTP 403; acesso via porta 8443 (não‑padrão) | Indica tentativa de servir conteúdo controlado; retorno 403 pode ser medida de bloqueio ou página vazia de teste. |
| **cURL (HTTP/1.1)** | 403 Forbidden, Server: Cloudflare, cabeçalhos “cf‑cache‑status: DYNAMIC” | O site está protegido por Cloudflare; o conteúdo real pode estar condicionado a cabeçalhos, cookies ou origem. |
| **Certificado TLS** | Emitido por Google Trust Services, SAN = `acessoportalatendimento.app`, `*.acessoportalatendimento.app` | Certificado válido e confiável, prática comum de atores maliciosos para ganhar confiança. |
| **OTX Pulses** | Nenhum registro | Não há associação pública a campanhas conhecidas, porém a ausência pode ser devido à pouca exposição. |

### Possíveis Táticas/Procedimentos (ATT&CK) observados
- **T1071 – Application Layer Protocol (HTTP/HTTPS)** – uso de protocolos web para entrega ou controle.  
- **T1105 – Ingress Tool Transfer** – possibilidade de transferência de ferramentas/payloads via sub‑domínio temporário.  
- **T1190 – Exploit Public-Facing Application** – portas não‑padrão (8443) podem indicar serviço não‑público usado como “back‑door”.  
- **T1566.002 – Phishing: Spearphishing Link** – sub‑domínio aleatório pode ser incorporado em e‑mails de phishing.  

Não há evidência direta de **botnet** ou **malware** associado, mas a postura de infraestrutura (CDN, registros privados) combina com padrões usados por atores que desejam esconder a origem e acelerar a criação de novos “landing pages”.

---  

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS13335 – Cloudflare, Inc.** (para ambos IPv4 e IPv6) |
| **ISP / Provedor** | Cloudflare (serviço de CDN / DNS‑proteção) |
| **País / Região** | Estados Unidos (anycast – pontos de presença em várias regiões, predominantemente NA) |
| **Cidade** | Não determinável (anycast). Respostas de teste geralmente vêm de data‑centers em **São Francisco/LA** ou **Nova‑York**. |
| **Endereços IPv4** | 104.21.7.199, 172.67.156.69 |
| **Endereços IPv6** | 2606:4700:3032::6815:7c7, 2606:4700:3034::ac43:9c45 |
| **DNSSEC** | Não há assinatura (AD = false). |
| **Certificado TLS** | Emissor: Google Trust Services; validade 04/07/2025 – 02/10/2025; SAN inclui curinga `*.acessoportalatendimento.app`. |

---  

## 4. Domínios e IPs Relacionados
| Tipo | Indicador | Observação |
|------|-----------|------------|
| **Domínio de nível‑apex** | `acessoportalatendimento.app` | Domínio principal; pode hospedar outros sub‑domínios. |
| **Sub‑domínio analisado** | `holmes456.acessoportalatendimento.app` | Sub‑domínio aleatório, possivelmente gerado por script automatizado. |
| **IPv4** | 104.21.7.199 | Cloudflare (AS13335). |
| **IPv4** | 172.67.156.69 | Cloudflare (AS13335). |
| **IPv6** | 2606:4700:3032::6815:7c7 | Cloudflare. |
| **IPv6** | 2606:4700:3034::ac43:9c45 | Cloudflare. |

> **Nota:** Como o domínio está hospedado em uma CDN, os mesmos endereços IP atendem a múltiplos domínios. Qualquer associação adicional deve ser verificada por meio de consultas passive‑DNS, histórico de resolução e correlação com outras fontes de inteligência.

---  

## 5. Recomendações de Investigações
1. **Monitoramento de DNS**  
   - Crie alertas para resolução de `*.acessoportalatendimento.app` nos logs de DNS (SIEM, DNS‑Firewall).  
   - Verifique variações de TTL e novos A/AAAA records que possam indicar mudanças de infraestrutura.  

2. **Análise de Tráfego de Rede**  
   - Correlacione solicitações HTTP/HTTPS para os IPs da Cloudflare (104.21.7.199, 172.67.156.69) com fluxos internos.  
   - Preste atenção a conexões a portas não‑padrão (ex.: 8443) ou a protocolos de túnel (HTTP CONNECT, WebSocket).  

3. **Inspeção de Conteúdo Web**  
   - Capture o corpo das respostas (mesmo que 403) e analise cabeçalhos, cookies e scripts embutidos.  
   - Use ferramentas de sandbox (Cuckoo, CAPE) para abrir a URL em um ambiente controlado e observar comportamento (download de arquivos, redirecionamentos, execução de JavaScript).  

4. **Enriquecimento Passivo‑DNS e Histórico WHOIS**  
   - Consulte serviços como SecurityTrails, RiskIQ ou DNSDB para identificar outros sub‑domínios que já apontaram para os mesmos IPs.  
   - Verifique se o domínio já esteve associado a listas de bloqueio (Spamhaus, Emerging Threats, etc.).  

5. **Correlações com Feeds de Ameaças**  
   - Busque hashes ou URLs presentes nos relatórios do URLScan.io em bases como URLhaus, PhishTank, Abuse.ch.  
   - Consulte feeds de indicadores de C2 (C2‑Tracker, MalwareBazaar) para possíveis pares domínio↔IP.  

6. **Análise de Certificado**  
   - Verifique a cadeia de confiança e a data de emissão; compare com padrões de renovação automática da Cloudflare.  
   - Observe se o certificado foi recentemente re‑emitido (sinal de mudança de controle).  

7. **Teste de Phishing**  
   - Procure por e‑mails ou mensagens que incluam URLs contendo `acessoportalatendimento.app`.  
   - Use o serviço de sandbox para analisar links curtos ou redirecionamentos que terminem no sub‑domínio.  

8. **Registro de Evidências**  
   - Armazene capturas de tela, logs HTTP, respostas de DNS e amostras de certificados para futura comparação e uso em relatórios de incidentes.  

---  

## 6. Conclusão
O domínio **holmes456.acessoportalatendimento.app** não apresenta indicadores de malware reconhecidos por scanners de antivírus, mas exibe atributos típicos de **infraestrutura de uso temporário e ofuscado** (registro recente, sub‑domínio aleatório, hospedagem em CDN com certificado legítimo). Tais características são frequentemente exploradas por atores de ameaça para **phishing, hospedagem de payloads ou como ponto de comando e controle**.

Dado o **risco médio‑alto** implícito pela falta de reputação consolidada e o potencial de abuso em campanhas futuras, recomenda‑se **monitoramento ativo**, **correlação com logs internos** e **investigações adicionais** conforme as etapas listadas. O domínio deve ser incluído em listas de observação e, caso ocorram sinais de atividade maliciosa (ex.: tráfego inesperado, downloads de arquivos suspeitos, e‑mails de phishing contendo o domínio), ele pode ser provado para bloqueio em perímetros de segurança.  