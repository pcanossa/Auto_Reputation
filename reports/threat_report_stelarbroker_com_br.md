# Relatório de Threat Intelligence – Domínio **stelarbroker.com.br**

> **Fonte dos dados**: WHOIS (registro.br), VirusTotal, AlienVault OTX, Urlscan.io.  
> **Última coleta VirusTotal**: 2025‑10‑01 16:04:27 (UTC).

---

## 1. Resumo Executivo
O domínio **stelarbroker.com.br** foi registrado em **23/09/2025** por “Marcio Vinicius Costa de Souza” através da GoDaddy (provedor de DNS). Ele resolve para dois endereços IPv4 – **3.33.130.190** e **15.197.148.33** – ambos pertencentes à Amazon Web Services (AS14618). Não há registros de atividade maliciosa em bases de inteligência conhecidas: o VirusTotal reporta **0 deteções** (95 análises “undetected”), o AlienVault OTX não possui pulsos ou relacionamentos com malware/botnet, e o Urlscan.io não retornou resultados. O certificado TLS é emitido pela **GoDaddy Secure Certificate Authority – G2** (valido até 28/09/2026) e o JARM do serviço web indica um fingerprint padrão de servidores web modernos. Até o momento, não há indícios claros de uso para phishing, C2 ou distribuição de malware.

---

## 2. Análise de Comportamento
| Indicador | Observação |
|-----------|------------|
| **WHOIS** | Domínio recém‑criado (23/09/2025), contato de e‑mail genérico (`higorperfilbatista@gmail.com`). |
| **DNS** | Dois registros **A** (3.33.130.190, 15.197.148.33) apontam para infraestrutura AWS, com TTL de 600 s. |
| **TLS/HTTPS** | Certificado válido, emitido por GoDaddy, sem sinais de comprometimento. |
| **Reputação VT** | 0/95 engines marcaram como “undetected”. Nenhuma classificação de “malicious” ou “suspicious”. |
| **OTX** | Nenhum pulso, nem links para malware ou campanhas de phishing. |
| **Urlscan.io** | Nenhum artefato encontrado – o domínio ainda não foi submetido a varreduras públicas. |
| **JARM** | `3fd3fd20d00000000043d3fd3fd43d9d4f83ac87494648a3bed4ab670795cd` – corresponde a um fingerprint comum de servidores Nginx/Apache configurados com TLS moderno. |

**Conclusão comportamental:** Não há evidências de atividade maliciosa conhecida. A presença em AWS pode ser legítima (sites corporativos, landing pages ou serviços internos). Contudo, a combinação de um domínio recém‑criado, proprietário sem histórico público e infra‑estrutura de nuvem pública requer **monitoramento contínuo**, visto que ataques de “infrastructure‑as‑code” (criação rápida de domínios e uso de cloud) são típicos de campanhas de phishing ou de distribuição de payloads temporários.

---

## 3. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS14618 – Amazon.com, Inc.** (para ambos os IPs 3.33.130.190 e 15.197.148.33) |
| **ISP / Provedor** | Amazon Web Services (AWS) |
| **Localização dos IPs** | <ul><li>3.33.130.190 – Estados Unidos (Virginia – região “us-east-1”)</li><li>15.197.148.33 – Estados Unidos (Oregon – região “us-west-2”)</li></ul> |
| **Cidade / Estado / País (domínio)** | Não aplicável – registro brasileiro (BR), porém a infraestrutura aponta para data‑centers norte‑americanas. |
| **Registro de Domínio** | **GoDaddy** (provedor “GODADDY (86)”). |
| **Data de Criação** | 23/09/2025 (válido até 23/09/2026). |
| **Nome do Responsável** | Marcio Vinicius Costa de Souza (e‑mail: `higorperfilbatista@gmail.com`). |

---

## 4. Domínios e IPs Relacionados

| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio analisado** | `stelarbroker.com.br` | - |
| **Registros DNS A** | `3.33.130.190`  (AWS – us-east-1) | Nenhuma lista de bloqueio conhecida. |
| | `15.197.148.33` (AWS – us-west-2) | Nenhuma lista de bloqueio conhecida. |
| **Nameservers** | `ns65.domaincontrol.com` <br> `ns66.domaincontrol.com` | Servidores da GoDaddy. |
| **Domínios “cousins”** | Nenhum outro domínio listado nos relatórios (OTX, VT) como relacionado. |
| **IPs em feeds de malware** | Não aparecem em feeds públicos (VT, AlienVault, AbuseIPDB, etc.) até a data da coleta. |

---

## 5. Recomendações de Investigação

1. **Monitoramento de DNS e IPs**  
   - Adicionar ambos os endereços IP (3.33.130.190, 15.197.148.33) a um **watchlist** em soluções de SIEM/IPS.  
   - Configurar alertas de criação de novos registros **A/AAAA/CNAME** associados ao domínio.

2. **Análise de tráfego**  
   - Verificar logs de firewall e proxy para identificar comunicações originadas ou destinadas a `stelarbroker.com.br` ou aos IPs acima nos últimos 30 dias.  
   - Inspecionar cabeçalhos HTTP (User‑Agent, Referer) para evidenciar possíveis campanhas de phishing ou download de payloads.

3. **Varredura de conteúdo web**  
   - Executar um **crawl** manual ou automatizado (ex.: `wget`, `curl`, `browserstack`) para capturar o conteúdo público do site (se houver) e analisar por indicadores de **phishing**, **malware dropper** ou **credenciais**.  
   - Utilizar ferramentas de sandbox (Cuckoo, VirusTotal URL) para analisar eventuais páginas ou arquivos servidos.

4. **Inteligência de reputação adicional**  
   - Consultar feeds de **Passive DNS** (PassiveTotal, SecurityTrails) para histórico de resolução desses IPs e possíveis mudanças de uso.  
   - Verificar **Certificate Transparency logs** para detectar novos certificados emitidos para o domínio ou sub‑domínios.

5. **Engajamento com provedor**  
   - Caso ocorram sinais de abuso (e.g., tentativas de phishing ou distribuição de malware), abrir ticket com **GoDaddy** (abuse@secureserver.net) e com a **AWS Abuse** (abuse@amazonaws.com) apontando os IPs suspeitos.

6. **Atualização contínua**  
   - Agendar nova coleta de dados em 7‑14 dias para validar se o domínio permanece inerte ou se surgem novos indicadores (pulsos OTX, detecções VT, inclusão em blocklists).

---

> **Nota:** Este relatório tem como objetivo apresentar o panorama de risco atual do domínio **stelarbroker.com.br** com base nas fontes disponíveis. Não há evidências de atividade maliciosa confirmada, mas a ausência de histórico e a utilização de infraestrutura de nuvem pública demandam vigilância constante.