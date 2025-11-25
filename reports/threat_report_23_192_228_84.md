# Relatório de Threat Intelligence – IP **23.192.228.84**

> **Fonte dos dados**: Shodan, IPInfo.io, URLScan.io, VirusTotal (sem resultados divulgados), AbuseIPDB, WHOIS (MarkMonitor), AlienVault OTX.  
> **Última coleta Shodan**: 2025‑11‑25  

---

## 1. Resumo Executivo
O endereço **23.192.228.84** pertence à rede de entrega de conteúdo (CDN) da **Akamai Technologies, Inc.** (ASN AS20940) e está localizado em **San Jose, Califórnia, EUA**. O host responde nas portas **80 (HTTP)** e **443 (HTTPS)**, entregando o conteúdo padrão “Example Domain”. Não há indícios de atividade de botnet, scanners de portas ou serviços de comando‑e‑controle (C2). O score de abuso na AbuseIPDB é **1/100**, indicando quase inexistência de relatos de uso malicioso. Não foram encontradas vulnerabilidades (CVEs) associadas ao host nos dados de Shodan. O IP aparece em múltiplas varreduras do URLScan.io simplesmente porque domínios que utilizam o serviço de CDN da Akamai (ex.: *example.com*, *elitemancer150.info*, etc.) resolvem para ele.

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|------|-----------|---------------|
| **Shodan** | Tags: *cdn*; Hostnames: `a23-192-228-84.deploy.static.akamaitechnologies.com`, `example.com`; Serviços HTTP/HTTPS que retornam a página “Example Domain”. | Indica que o endereço faz parte da infraestrutura de entrega de conteúdo da Akamai, servindo como ponto de presença (PoP) para sites que utilizam a CDN. |
| **AbuseIPDB** | Abuse Confidence Score **1**, apenas 2 relatos (último em 2025‑10‑29). | Nenhum padrão de abuso significativo. |
| **AlienVault OTX** | Nenhum pulso de ameaça associado. | Não há relatos de campanhas ou indicadores de comprometimento. |
| **URLScan.io** | Diversas submissões de URLs (ex.: `example.com`, `elitemancer150.info`, `sign‑in.top`) apontam para este IP. | Reflete o uso da CDN para múltiplos domínios, inclusive alguns que podem ser “suspicious”. Contudo, o IP em si não demonstra comportamento ativo de ataque; ele apenas hospeda conteúdo em cache. |
| **VirusTotal** | Resposta vazia/sem dados relevantes. | Não há deteções de malware ou arquivos suspeitos associados ao IP. |

**Conclusão de comportamento:** Não há evidência de que o IP esteja atuando como botnet, scanner ou servidor C2. Seu papel parece ser puramente de entrega de conteúdos estáticos via CDN, o que é típico e esperado para endereços da Akamai.

---

## 3. Superfície de Ataque
### 3.1 Portas abertas e serviços
| Porta | Protocolo | Serviço | Comentário |
|------|-----------|---------|------------|
| **80** | TCP | HTTP – Servindo página padrão “Example Domain”. | Endpoint público sem aplicação específica; URL retornam apenas conteúdo estático. |
| **443** | TCP | HTTPS – Certificado SSL emitido por DigiCert (CN=`*.example.com`). | Certificado válido até 15/01/2026. Utiliza HTTP/3 (ALPN h3). |

### 3.2 Vulnerabilidades (CVEs) identificadas
- **Nenhuma CVE** listada nos resultados de Shodan para este host.  
- Como o IP pertence a uma CDN, vulnerabilidades típicas de servidores web (ex.: *CVE‑2023‑xxxx* em Apache/Nginx) não são detectáveis diretamente; a camada de origem (backend) pode estar protegida ou mascarada pela Akamai.

---

## 4. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20940** – Akamai Technologies, Inc. |
| **ISP** | **Akamai International B.V.** |
| **Organização** | **Akamai Technologies, Inc.** |
| **País** | **Estados Unidos (US)** |
| **Região / Estado** | **California** |
| **Cidade** | **San Jose** |
| **Latitude/Longitude** | **37.3394, -121.8950** |
| **Hostnames** | `a23-192-228-84.deploy.static.akamaitechnologies.com`, `example.com` |
| **Domínios associados** | `akamaitechnologies.com`, `example.com` (via CDN) |

---

## 5. Recomendações de Investigação
1. **Correlações de logs internos**  
   - Verifique nos firewalls, proxies e SIEMs se há tráfego inesperado para ou proveniente de `23.192.228.84`.  
   - Dê atenção a solicitações de **HTTP/3** ou a picos de volume que possam indicar abuso da CDN (ex.: DDoS reflection).

2. **Revisão de feeds de ameaças**  
   - Consulte fontes como **OTX**, **MISP**, **Passive DNS** e **Threat Intelligence Platforms** para confirmar se novos indicadores envolvendo este IP foram publicados recentemente.  
   - Atualize listas de bloqueio/allowlist com base em eventuais mudanças de comportamento.

3. **Análise de domínios “suspicious”**  
   - Embora o IP pareça legítimo, alguns domínios resolvendo para ele (ex.: `elitemancer150.info`, `sign‑in.top`) podem ser usados por atores maliciosos para se esconder atrás da CDN.  
   - Realize *sandboxing* ou *URL reputation* nesses domínios antes de autorizar acesso interno.

4. **Monitoramento contínuo**  
   - Configure alertas no **Shodan Monitor** ou em serviços como **Censys**, **RiskIQ**, para detectar alterações de portas, banners ou novos serviços.  
   - Acompanhe mudanças no **certificado SSL** (renovações, alterações de SAN) que possam indicar mudança de proprietário ou uso.

5. **Validação de configuração de CDN**  
   - Caso sua organização utilize a Akamai, confirme que o IP está listado como parte da sua topologia de entrega e que não há *edge‑servers* comprometidos.  
   - Caso contrário, mantenha o IP em listas de **allow** apenas para tráfego de conteúdo esperado (ex.: entrega de assets estáticos).

---

## 6. Considerações Finais
O endereço **23.192.228.84** apresenta um perfil típico de um *edge server* da Akamai CDN, com baixa pontuação de abuso e sem indicadores de comprometimento. A presença de múltiplos domínios (alguns possivelmente maliciosos) que apontam para este IP deve ser tratada como **uso legítimo de infraestrutura compartilhada**, mas requer vigilância para evitar **false positives** em filtros de segurança. Não há vulnerabilidades específicas associadas ao host que justifiquem bloqueios imediatos; a postura recomendada é monitorar atividade e manter boas práticas de correlação de logs e inteligência de ameaças.