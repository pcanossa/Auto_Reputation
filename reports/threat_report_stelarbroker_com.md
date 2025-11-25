# Relatório de Threat Intelligence – Domínio **stelarbroker.com**

> **Fonte dos dados**: WHOIS (whois.godaddy.com), VirusTotal (API v3), Urlscan.io, AlienVault OTX, consultas DNS públicas.  
> **Última coleta VirusTotal**: 2025‑11‑25 (timestamp 1761373403).

---

## 1. Resumo Executivo
O domínio **stelarbroker.com** foi registrado em 11 / 09 / 2025 via GoDaddy, com proteção de privacidade (Domains By Proxy). Está apontado para dois endereços IPv4 que pertencem à rede da Cloudflare (AS13335 – Cloudflare, Inc.) e utiliza os servidores de nomes *KINSLEY.NS.CLOUDFLARE.COM* e *ROMMY.NS.CLOUDFLARE.COM*.  

No VirusTotal, o domínio recebeu **1 “malicious”** e **2 “suspicious”** entre 61 análises “harmless”. O motor “CRDF” o classificou como **malicious**, enquanto “Bfore.Ai PreCrime” e “Gridinsoft” o marcaram como **suspicious**. Nenhum pulso (pulse) foi encontrado no AlienVault OTX, e o Urlscan.io não retornou resultados.  

Apesar da infraestrutura ser baseada em Cloudflare – normalmente usada para mitigação e CDN – a presença de rótulos “malicious”/“suspicious” indica que o domínio já foi associado a alguma atividade potencialmente perigosa (ex.: hospedagem de conteúdo phishing ou comando‑e‑controle) e pode estar sendo usado como fachada. A falta de histórico público e a recente data de criação sugerem que o domínio pode estar em fase de “bootstrapping” para atividades maliciosas emergentes.

---

## 2. Análise de Comportamento
| Evidência | Interpretação |
|-----------|----------------|
| **Rótulo “malicious” (CRDF)** | Indica que ao menos uma fonte de inteligência classificou o domínio como associado a atividade maliciosa (ex.: phishing, C2, distribuição de malware). |
| **Rótulo “suspicious” (Bfore.Ai, Gridinsoft)** | Sinal de que o domínio apresenta indícios de uso indevido, ainda que não haja consenso entre todos os motores. |
| **Nenhum registro em OTX ou URLhaus** | Ainda não há amplo compartilhamento da ameaça, possivelmente por ser um domínio novo ou de uso restrito. |
| **Uso de Cloudflare (IP 104.21.55.89 & 172.67.146.94)** | Cloudflare oculta o IP de origem real, prática comum tanto em sites legítimos quanto em infra‑estruturas de ataque para esconder a fonte. |
| **Certificado TLS válido (Google Trust Services, emitido 2025‑09‑15, expira 2025‑12‑14)** | Possui HTTPS configurado corretamente; criminosos costumam garantir certificados válidos para aumentar a confiança dos alvos. |
| **Ausência de áreas suspeitas no WHOIS (registrado privadamente)** | Ocultamento de identidade do proprietário, estratégia típica de agentes maliciosos. |
| **Domínio recém‑criado (menos de 3 meses)** | Domínios novos são frequentemente utilizados em campanhas de phishing ou para “fast‑flux”. |

**Conclusão:** Há indícios suficientes de que *stelarbroker.com* pode estar sendo usado como ponto de apoio para atividades maliciosas (ex.: phishing, redirecionamento para payloads, ou como fachada de C2). A ausência de ampla divulgação pode indicar uma campanha ainda em fase inicial ou segmentada.

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS13335 – Cloudflare, Inc.** |
| **Provedor (ISP)** | **Cloudflare, Inc.** (serviço de CDN/DNS) |
| **Localização (IP 104.21.55.89)** | United States – São Francisco, CA (dados de geolocalização dos blocos Cloudflare). |
| **Localização (IP 172.67.146.94)** | United States – São Francisco, CA (mesma origem Cloudflare). |
| **Cidade / Região / País (registro WHOIS)** | Não divulgado (registrado privadamente). |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **Nameservers** | `KINSLEY.NS.CLOUDFLARE.COM`, `ROMMY.NS.CLOUDFLARE.COM` | Servidores de nomes da Cloudflare. |
| **Endereços IPv4** | `104.21.55.89` <br> `172.67.146.94` | Ambos pertencem ao bloco de IP da Cloudflare (AS13335). |
| **IPv6 (observados nas DNS records)** | `2606:4700:3036::6815:3759` <br> `2606:4700:3036::ac43:925e` | Também da Cloudflare. |
| **Domínios correlatos (wildcard no certificado)** | `*.stelarbroker.com` | Possível uso de sub‑domínios para diferentes propósitos. |
| **Outros domínios** | Não foram identificados relacionamentos adicionais nos feeds consultados. |

---

## 5. Recomendações (Próximos Passos)
1. **Monitoramento contínuo**  
   - Adicionar *stelarbroker.com* e seus IPs (`104.21.55.89`, `172.67.146.94`) a mecanismos de *watchlist* internos (SIEM, Firewalls, proxies).  
   - Configurar alertas em plataformas de threat intel (e.g., AbuseIPDB, VirusTotal, AlienVault OTX) para novos relatórios.

2. **Correlacionar com logs internos**  
   - Verificar os logs de firewall, proxy web e DNS internos em busca de conexões ou resoluções para o domínio/IPs nos últimos 30 dias.  
   - Analisar tráfego HTTP(S) para eventuais arquivos suspeitos, redirecionamentos ou downloads de payloads.

3. **Enriquecimento de Inteligência**  
   - Consultar feeds adicionais (e.g., Spamhaus, Censys, Shodan) para identificar outras observações desse IP na internet.  
   - Realizar consultas reversas de PTR e WHOIS para os IPs Cloudflare para detectar padrões de uso por outros domínios marcados.

4. **Análise de conteúdo**  
   - Caso haja tráfego HTTP(S) para o domínio, capturar a página ou recurso entregue e submetê‑los a sandbox (e.g., Cuckoo, FireEye) para inspeção de malware ou comportamento de phishing.  

5. **Avaliar necessidade de bloqueio**  
   - Se houver evidência de comprometimento interno ou de usuários finais, considerar bloqueio temporário do domínio/IP no perímetro, mantendo monitoramento para validar falsos positivos.

6. **Documentação e compartilhamento**  
   - Documentar todas as descobertas e, se confirmado comportamento malicioso, submeter ao reposicionamento de indicadores (IoC) em fontes públicas (e.g., MISP, Abuse.ch) para benefício da comunidade.

---

*Este relatório tem como objetivo compilar e analisar os indicadores disponíveis sobre **stelarbroker.com**, facilitando a tomada de decisão de segurança. Não inclui recomendações técnicas de mitigação de vulnerabilidades específicas do domínio.*