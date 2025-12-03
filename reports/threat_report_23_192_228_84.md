# Relatório de Threat Intelligence – IP **23.192.228.84**

> **Fonte dos dados**: Shodan, IPInfo.io, URLScan.io, VirusTotal (sem resultados exibidos), AbuseIPDB, WHOIS (MarkMonitor), AlienVault OTX.  
> **Timestamp da Análise**: 2025-12-03T16:39:57.769992.

---

## 1. Resumo Executivo
O endereço **23.192.228.84** pertence ao bloco de rede da **Akamai Technologies, Inc.** (ASN AS20940) e está localizado em **San Jose, Califórnia, EUA**. O IP funciona como um ponto de presença (PoP) da rede de distribuição de conteúdo (CDN) da Akamai, servindo tráfego HTTP/HTTPS nas portas **80/tcp** e **443/tcp**. O banner HTTP revela o serviço **AkamaiGHost**, típico de servidores de edge da Akamai. Não foram encontradas vulnerabilidades CVE associadas ao host no Shodan, nem há indícios claros de atividade de botnet ou de comando‑e‑controle. Contudo, o IP aparece como origem de múltiplas varreduras de URL em sites de diferentes categorias, incluindo alguns marcados por analistas como potenciais phishing (ex.: *bullmetal.top*). O risco principal está relacionado ao uso da CDN para hospedar conteúdo de terceiros; se algum desses sites for mal‑intencionado, o IP pode ser associado a atividades indesejadas por efeitos colaterais.

---

## 2. Análise de Comportamento
| Fonte | Indicador | Interpretação |
|-------|-----------|---------------|
| **Shodan** | Tags: `cdn` | O host está claramente registrado como parte de uma rede de entrega de conteúdo. |
| | Open ports: 80, 443 | Serviços web padrão de entrega de conteúdo. |
| | HTTP/1.0 400 Bad Request (AkamaiGHost) | Resposta típica de um edge server quando a URL requisitada não corresponde a nenhum conteúdo armazenado. |
| **URLScan.io** | Mais de 30 varreduras de URLs diferentes (ex.: *example.com*, *bananguide.com*, *ros-supplier.com*, *bullmetal.top*). | O IP fornece conteúdo para inúmeros domínios, alguns aparentemente legítimos (*example.com*) e outros com tags de possível ameaça (*bullmetal.top*). |
| | Domínios com tags `falconsandbox` | Indicam que foram analisados em sandbox de malware, mas não confirmam que o IP seja o agente malicioso. |
| **AbuseIPDB** | Abuse Confidence Score: **1** (baixo) | Poucas denúncias; a maioria dos relatórios são de uso legítimo da CDN. |
| **AlienVault OTX** | Nenhum pulso associado | Não há relatos ativos de uso do IP em campanhas conhecidas. |
| **WHOIS / RDAP** | Registrado como *Akamai Technologies, Inc.*; ISP: *Akamai International B.V.* | Confirma propriedade de infraestrutura de CDN. |
| **VirusTotal** | Resposta vazia/no data | Não há amostras de arquivos ou URLs associadas ao IP que tenham sido analisadas. |

**Conclusão comportamental:**  
O IP **23.192.228.84** age como um ponto de entrega de conteúdo da Akamai. Não há evidências diretas de que ele opere como servidor de comando‑e‑controle, scanner automatizado ou botnet. O risco deriva da possibilidade de que sites mal‑intencionados utilizem a CDN para servir payloads ou phishing, fazendo com que o IP seja incluído em listas de observação de ameaças por *contaminação por terceiros*.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços
| Porta | Protocolo | Serviço / Tecnologia | Comentário |
|-------|-----------|----------------------|------------|
| **80** | TCP | HTTP (AkamaiGHost) | Servidor web de edge da Akamai; responde 400 Bad Request quando a URL é inválida. |
| **443** | TCP | HTTPS (AkamaiGHost) | Servidor TLS com certificado ***.example.com** emitido pela **DigiCert Global G3 TLS ECC SHA384 2020 CA1**; indica uso de TLS/1.3 (HTTP/3 habilitado). |

### 3.2 Vulnerabilidades (CVEs) Identificadas
- **Nenhum CVE** foi listado nas informações extraídas do Shodan para este host.  
- Como o serviço é um *edge server* da Akamai, as vulnerabilidades conhecidas de componentes internos (ex.: OpenSSL, NGINX) são gerenciadas e patchadas pela própria Akamai; nenhum ponto vulnerável foi exposto publicamente.

### 3.3 Potenciais Riscos Relacionados à Superfície
- **Exposição de Certificado Wildcard (`*.example.com`)**: Embora legítimo para fins de CDN, pode ser reutilizado em ataques de *mis‑issued* se o certificado for comprometido.  
- **HTTP/3 (QUIC) habilitado**: Embora ofereça performance, também pode dificultar a inspeção de tráfego em alguns dispositivos de segurança.  
- **Uso por domínios suspeitos**: Sites como *bullmetal.top* (marcados como phishing) utilizam o mesmo IP, possibilitando que ferramentas de reputação listem o IP como “suspeito”.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS20940 – Akamai Technologies, Inc.** |
| **ISP / Provedor** | **Akamai International B.V.** |
| **Organização** | **Akamai Technologies, Inc.** |
| **País** | **Estados Unidos (US)** |
| **Região / Estado** | **California** |
| **Cidade** | **San Jose** |
| **Latitude/Longitude** | **37.3394, -121.8950** |
| **Código Postal** | **95025** |
| **Fuso horário** | **America/Los_Angeles** |

---

## 5. Recomendações

1. **Correlacionar com logs internos**  
   - Verifique os registros de firewall, proxy e IDS/IPS para identificar tráfego inbound/outbound envolvendo o IP **23.192.228.84**.  
   - Avalie se há solicitações suspeitas (ex.: tentativas de GET em caminhos não existentes ou uploads de arquivos).

2. **Monitoramento de reputação**  
   - Inscreva o IP em feeds de inteligência de ameaças (OTX, AbuseIPDB, Spamhaus, etc.) e habilite notificações de mudanças de score.  
   - Atente para eventuais aumentos no Abuse Confidence Score ou inclusão em listas de phishing.

3. **Análise de domínios associados**  
   - Crie um inventário dos domínios que resolvem para este IP (via DNS reverse lookup e pesquisas Shodan).  
   - Priorize a inspeção de domínios marcados como *phishing*, *malware* ou com tags de sandbox.

4. **Inspeção de tráfego TLS**  
   - Caso a organização utilize inspeção SSL/TLS, garanta que os certificados da Akamai sejam reconhecidos e que o *decryption* não cause falhas de validação.  
   - Monitore a negociação de HTTP/3, pois pode interferir em políticas de segurança baseadas em inspeção de camada 7.

5. **Avaliação de risco de “third‑party content”**  
   - Considere a implementação de políticas de *content security policy* (CSP) que restrinjam recursos carregados de CDNs não autorizados.  
   - Avalie a necessidade de *allow‑list* apenas de domínios ou sub‑domínios conhecidos e confiáveis que utilizam a Akamai.

6. **Relatório de incidentes**  
   - Caso ocorram detecções de comportamento malicioso originado de sites hospedados neste IP, registre o incidente e compartilhe com a equipe de C‑IRT e, se pertinente, com a própria Akamai (via canal de abuse).

---

## 6. Considerações Finais
O endereço **23.192.228.84** é parte da infraestrutura de entrega de conteúdo da Akamai, amplamente utilizada por milhões de sites. Não há indícios de que ele seja um ponto de controle malicioso por si só; entretanto, o uso compartilhado da CDN significa que a reputação do IP pode ser afetada por terceiros que hospedam conteúdo malicioso. A estratégia de monitoramento contínuo, correlação com logs internos e análise de domínios associados minimizará o risco de falsos positivos e permitirá respostas rápidas caso alguma campanha de abuso seja detectada.