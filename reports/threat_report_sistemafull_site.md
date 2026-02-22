# Relatório de Threat Intelligence – Domínio **sistemafull.site**

> **Fonte dos dados**: WHOIS (whois.domaintools.com), VirusTotal (API v3), URLScan.io, crt.sh, DNSDumpster, Passive DNS (SecurityTrails – quando disponível), consultas DNS públicas (dig, dnspython), inspeção HTTP (cURL).  
> **Timestamp da Análise**: 2026-02-22T04:30:13.838406.  

---

## 1. Resumo Executivo
O domínio **sistemafull.site** foi registrado em 04‑06‑2025 (registro privado) sob o TLD `.site`, tipicamente associado a registros de baixo custo e anonimato. Ele resolve para o endereço IPv4 **95.111.233.242** (ASN 51167 – **Contabo GmbH**, Alemanha) com DNS hospedado em **Cloudflare** (ns1/2 `norman.ns.cloudflare.com`, `roxy.ns.cloudflare.com`). As análises públicas apresentam um panorama divergente:  

* **VirusTotal** – 59/93 scanners classificam como *harmless*; nenhum apontamento de *malicious* ou *suspicious*.  
* **URLScan.io** – relatam presença de um site “Websoft9 Applications Hosting Platform”, sem redirecionamentos externos, porém sem cabeçalhos de segurança (HSTS, CSP) e sem TLS efetivo.  
* **crt.sh** – mais de 60 certificados emitidos (Let’s Encrypt, GoDaddy, Cloudflare) inclusive para sub‑domínios (*\*.sistemafull.site*), indicando capacidade de criar hosts temporários.  
* **DNS/DNSSEC** – ausência de assinatura DNSSEC, TTL curto (300 s) e única entrada A, o que pode ser típico de “fast‑flux” ou de hospedagem temporária.  

Nenhum feed de inteligência (OTX, PhishTank, Spamhaus) relaciona o domínio a campanhas de phishing, botnets ou C2. Contudo, a combinação de **registro recente**, **uso de serviços de hospedagem de baixo custo**, **ausência de hardening** e **emissão frequente de certificados** sugere que o domínio possa ser usado como **infraestrutura de apoio** (landing pages, distribuição de payloads ou redirecionamento) por atores maliciosos. Avaliação de risco: **moderado a alto**, recomendando monitoramento ativo.

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **VirusTotal (v3)** | 59 *harmless*, 34 *undetected*, 0 *malicious*/*suspicious* | O domínio ainda não foi amplamente usado em ataques conhecidos, mas a ausência de detecção não garante inocuidade. |
| **URLScan.io** (várias varreduras) | Resposta HTTP 200 OK com título “Websoft9 Applications Hosting Platform”; ausência de TLS, sem cabeçalhos de segurança; arquivos `.data` não reconhecidos por antivírus. | Site parcialmente configurado; pode servir como *dropper* ou *staging* para arquivos maliciosos que ainda não foram identificados. |
| **crt.sh (certificados)** | > 60 certificados emitidos (Let’s Encrypt, GoDaddy, Cloudflare) para `sistemafull.site` e múltiplos sub‑domínios (ex.: `bad.sistemafull.site`, `api.sistemafull.site`). | Capacidade de gerar rapidamente novos sub‑domínios, típica de infraestruturas “fast‑flux” ou de kits de phishing que criam hosts descartáveis. |
| **DNS (dig)** | Um único registro A = 95.111.233.242; TTL = 300 s; sem DNSSEC. | Configuração simples, porém baixa proteção contra envenenamento de DNS; fácil de mudar o apontamento rapidamente. |
| **Whois** | Registro privado, data de criação 04‑06‑2025, validade 1 ano, registrador GoDaddy. | Anonimato dificulta atribuição; prática comum em domínios criados para uso malicioso. |
| **Passive DNS / DNSDumpster** | Apenas o IP 95.111.233.242 aparece; sem histórico significativo de resolução ou mudança de IP. | Ainda não houve “churn” de IPs, mas a monitoração deve observar possíveis alterações. |

**Conclusão comportamental** – Não há evidência direta de botnet, C2 ou phishing ativo, porém o domínio apresenta indicadores (registro recente, infraestrutura de baixo custo, ausência de segurança) que facilitam seu uso como *capa* ou *staging* para atividades maliciosas.  

### Táticas/Procedimentos (ATT&CK) possivelmente associados
| ID | Técnica | Justificativa |
|----|----------|---------------|
| T1071 | Application Layer Protocol (HTTP) | Site entrega conteúdo via HTTP sem criptografia. |
| T1027 | Obfuscated Files or Information | Arquivos `.data` não reconhecidos podem ser binários ofuscados. |
| T1105 | Ingress Tool Transfer | Possível transferência de payloads para clientes que acessam o site. |
| T1190 | Exploit Public-Facing Application | A falta de hardening pode facilitar exploração. |
| T1566.002 | Phishing: Spearphishing Link (sem evidência ainda) | Sub‑domínios temporários podem ser usados em campanhas de e‑mail. |

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS51167 – Contabo GmbH** (provedor de data‑center na Alemanha). |
| **ISP / Provedor** | Contabo GmbH (hosting de baixo custo). |
| **País / Região** | **França** (cidade Lauterbourg – localidade atribuída ao IP 95.111.233.242). |
| **Endereço IPv4** | 95.111.233.242 |
| **IPv6** | Não há registro AAAA. |
| **Servidor HTTP** | `openresty` (versão não especificada). |
| **Portas abertas** | 80/tcp (HTTP). |
| **DNSSEC** | Não habilitado. |
| **NS** | `norman.ns.cloudflare.com`, `roxy.ns.cloudflare.com` (Cloudflare). |
| **PTR (Reverse DNS)** | `vmi3079941.contaboserver.net` |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **IP principal** | `95.111.233.242` | Resolvido por `sistemafull.site`. |
| **Sub‑domínios detectados** (via crt.sh / DNSDumpster) | `bad.sistemafull.site`, `api.sistemafull.site`, `nada.sistemafull.site`, `base1.sistemafull.site`, `base2.sistemafull.site` | Possíveis hosts temporários; nenhum ainda marcado como malicioso. |
| **Domínios citados em certificados** (wildcard) | `*.sistemafull.site` | Permite criação livre de novos sub‑hosts. |
| **Domínios corrolacionados em feeds (nenhum encontrado)** | — | Não há pulsos OTX, PhishTank ou Spamhaus associados. |

> **Nota:** A lista completa de sub‑domínios pode crescer rapidamente por causa da emissão de certificados wildcard; recomenda‑se monitorar a zona DNS para novas criações.

---

## 5. Recomendações de Investigações Futuras
1. **Monitoramento de DNS** – Logar todas as consultas ao domínio e seus sub‑domínios nos dispositivos de segurança (DNS firewall, SIEM). Alertar sobre resoluções a IPs fora do escopo corporativo ou mudanças repentinas de IP.  
2. **Análise de tráfego HTTP(S)** – Capturar e inspecionar o conteúdo das requisições/respostas (especialmente arquivos `.data`). Utilizar sandbox (e.g., Cuckoo, FireEye) para examinar possíveis payloads.  
3. **Coleta de novos certificados** – Consultar periodicamentes o API do **crt.sh** ou **Censys** para detectar novos certificados wildcard que possam indicar criação de sub‑domínios maliciosos.  
4. **Verificação de listas de bloqueio** – Incluir o IP 95.111.233.242 e o FQDN `sistemafull.site` (e `*.sistemafull.site`) em blocklists de firewalls/Web‑proxy até que a necessidade de comunicação seja justificada.  
5. **Correlações com feeds de ameaças** – Consultar regularmente bases como **AbuseIPDB**, **Spamhaus DROP**, **Hybrid Analysis**, **OTX**, **MISP** para verificar se o IP ou os sub‑domínios aparecem em novos indicadores.  
6. **Análise de cabeçalhos HTTP** – Verificar a presença de cabeçalhos de segurança (HSTS, CSP, X‑Content‑Type‑Options) em futuras respostas; a falta pode indicar baixa maturidade de segurança dos operadores.  
7. **Revisão de certificados SSL/TLS** – Avaliar a validade, a cadeia de confiança e a emissão de novos certificados; certificados de curta validade (90 dias) podem ser usados para evitar lista negra de CAs.  
8. **Enriquecimento de WHOIS** – Monitorar alterações no registro (data de expiração, mudança de registrador ou de contato) que podem indicar “sale” de domínio para usos maliciosos.  

---

## 6. Conclusão
O domínio **sistemafull.site** ainda não possui indicadores de comprometimento *explícitos* em bases de ameaças reconhecidas, porém apresenta **vários fatores de risco** (registro recente, hospedagem em data‑center de baixo custo, ausência de DNSSEC, emissão de certificados wildcard, falta de hardening HTTP). Essas características são frequentemente observadas em infraestruturas utilizadas por atores maliciosos como *staging* ou *landing pages* para phishing e distribuição de malware.  

Recomendamos **tratá‑lo como risco moderado a alto**, mantendo vigilância constante sobre resoluções DNS, tráfego HTTP e mudanças de certificados, além de correlacionar os indicadores coletados com feeds de ameaças externos. Até que haja evidência de uso malicioso concreto, a política de bloqueio preventivo e monitoramento ativo é a postura mais prudente.