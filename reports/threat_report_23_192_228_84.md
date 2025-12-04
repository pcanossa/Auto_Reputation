# Relatório de Threat Intelligence – IP **23.192.228.84**

> **Fonte dos dados**: Shodan, IPInfo.io, URLScan.io, VirusTotal, AbuseIPDB, WHOIS, AlienVault OTX.  
> **Timestamp da Análise**: 2025-12-04T13:17:42.496678.

---

## 1️⃣ Resumo Executivo
O endereço **23.192.228.84** está associado à rede de entrega de conteúdo (CDN) da **Akamai Technologies, Inc.** (ASN AS20940). Ele está localizado em **San Jose, Califórnia, EUA**, e hospeda serviços HTTP/HTTPS nas portas **80/tcp** e **443/tcp**, ambos respondendo com o banner **AkamaiGHost** e retornando *400 Bad Request* para URLs inválidas. Não foram identificadas vulnerabilidades críticas (CVEs) diretamente expostas pelo Shodan. Os scores de abuso são quase nulos (AbuseIPDB = 1) e a maioria dos relatórios de URLScan.io corresponde a varreduras de teste (“example.com”) ou links de redirecionamento, sem indícios claros de atividades maliciosas. Não há evidências de botnet, C2 ou scanner dedicado; o IP parece ser um ponto legítimo de entrega de conteúdo Akamai.

---

## 2️⃣ Análise de Comportamento
| Fonte | Indicadores relevantes | Avaliação |
|-------|-----------------------|-----------|
| **Shodan** | Hostname `a23-192-228-84.deploy.static.akamaitechnologies.com`; tags: *cdn*; serviços HTTP/HTTPS com banner *AkamaiGHost*; últimas aparições em 2025‑12‑04. | Característica típica de um servidor Akamai CDN. |
| **IPInfo.io** | ASN AS20940, ISP Akamai International B.V., localização San Jose, CA. | Confirma propriedade da CDN. |
| **URLScan.io** | > 20 varreduras de `https://example.com/` e alguns links curtos (*href.li*) apontando para o IP. Nenhum conteúdo malicioso identificado nos relatórios. | Uso do IP para testes ou redirecionamentos legítimos; não há carga maliciosa conhecida. |
| **AbuseIPDB** | Abuse Confidence Score = 1 (muito baixo); 2 relatórios (último em 2025‑10‑29). | Pouca ou nenhuma queixa de abuso. |
| **AlienVault OTX** | Pulses genéricos que listam o IP como “related indicator” de tipo IPv4, sem classification de ameaça. | Não há associação direta a campanhas ou malware. |
| **VirusTotal** | Resposta vazia (sem detalhes fornecidos). | Nenhum resultado negativo ou positivo divulgado. |
| **WHOIS** | Domínio `akamaitechnologies.com` registrado por Akamai; múltiplos nameservers Akamai. | Reforça natureza de infraestrutura corporativa. |

**Conclusão:** Não há indícios robustos de que o IP esteja operando como botnet, servidor C2 ou scanner malicioso. O comportamento está alinhado a um ponto de presença (PoP) da Akamai, utilizado para entrega de conteúdo web.

---

## 3️⃣ Superfície de Ataque
### 3.1 Portas e Serviços
| Porta | Protocolo | Serviço / Banner | Observação |
|-------|-----------|------------------|------------|
| **80** | TCP | HTTP – *AkamaiGHost* (responde 400 Bad Request). | Porta típica de entrega de conteúdo web. |
| **443** | TCP | HTTPS – *AkamaiGHost* (certificado DigiCert TLS Hybrid ECC SHA384 2020). | Porta segura de entrega de conteúdo web. |

### 3.2 Vulnerabilidades (CVEs) Identificadas
- **Nenhuma CVE** foi listada nos dados de Shodan ou nas demais fontes. O certificado TLS está atualizado (válido até 2026-03-18) e não há serviços expostos que apresentem vulnerabilidades conhecidas.

> **Nota:** Caso existam vulnerabilidades em componentes internos da Akamai (não expostas ao público), elas não foram detectáveis pelos dados fornecidos.

---

## 4️⃣ Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20940 – Akamai Technologies, Inc.** |
| **ISP** | **Akamai International B.V.** |
| **Organização** | **Akamai Technologies, Inc.** |
| **Localização** | **San Jose**, **California**, **Estados Unidos (US)** |
| **Coordenadas** | 37.3394 N, ‑121.8950 W |
| **Hostname** | `a23-192-228-84.deploy.static.akamaitechnologies.com` |
| **Domínio associado** | `akamai.net` / `akamaitechnologies.com` |

---

## 5️⃣ Recomendações de Investigação
1. **Correlacionar logs de firewall / proxy** – Verificar se há tráfego inesperado oriundo ou destinado a este IP dentro do seu ambiente.  
2. **Consultar feeds de ameaça** – Incluir o IP em buscas de listas negras (e.g., Spamhaus, Emerging Threats) e monitorar atualizações.  
3. **Analisar padrões de acesso** – Caso haja conexões HTTPS, inspecionar SNI e cabeçalhos para confirmar se são solicitações legítimas de conteúdo ou possíveis tentativas de abuso (ex.: phishing via CDN).  
4. **Monitoramento contínuo** – Utilizar alertas de Shodan ou outras plataformas para detectar mudanças de portas, serviços ou aparição de novas tags (ex.: “malware”, “botnet”).  
5. **Revisar incidentes internos** – Se houver detecção de atividade suspeita (ex.: exfiltração de dados) envolvendo este IP, aprofundar análise de metadados de sessão (user‑agent, timestamps, ``Referer``).  
6. **Validar certificados** – Embora o certificado esteja válido, confirmar que não há uso de certificados falsificados em suas aplicações (ex.: MITM).  

---

## 6️⃣ Conclusão Geral
O IP **23.192.228.84** apresenta o perfil clássico de um ponto de presença da **Akamai CDN**, com serviços web padrão e sem evidências de comportamento malicioso ativo nos dados analisados. O risco associado é baixo, porém, como ocorre com infraestruturas de CDN amplamente utilizadas por terceiros, recomenda‑se manter vigilância regular e correlacionar o tráfego com eventos internos para garantir que não esteja sendo abusado como “proxy” por atores maliciosos.