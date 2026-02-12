# Relatório de Threat Intelligence – Domínio **qrserver.com**

> **Fonte dos dados**: WHOIS (Sysinternals), VirusTotal, Urlscan.io, AlienVault OTX, Consultas DNS (A Record), cURL, Análise de Certificados SSL/TLS (crt.sh), DNSDumpster, Listas de Phishing (PhishTank/OpenPhish).  
> **Timestamp da Análise**: 2026-02-10T17:51:16.730651.

## 1. Resumo Executivo
O domínio `qrserver.com` apresenta um perfil ambíguo e de alto risco, caracterizado por uma infraestrutura técnica legítima mas com associações históricas e comportamentais fortemente vinculadas a campanhas maliciosas. Registrado desde 2009 sob o registrador INWX GmbH, ele opera como um serviço de geração de QR codes. No entanto, a análise do AlienVault OTX revela sua presença em **50 pulses**, associando-o consistentemente a atividades de **Phishing, Command and Control (C2), e hospedagem de malware** (especificamente NewOrder.doc). O indicador mais crítico é a resolução DNS do domínio raiz para o endereço de loopback `127.0.0.1`, um padrão altamente anômalo e frequentemente utilizado em infraestruturas maliciosas sinkholed ou para evasão. Embora scanners como o VirusTotal o classifiquem como benigno (0 detecções) e seus certificados SSL apresentem um padrão de renovação legítimo, a combinação de seu histórico na OTX e o comportamento anômalo de DNS justificam classificá-lo como um **Indicador de Comprometimento (IoC)** e tratá-lo com risco **médio a alto**.

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|:---|:---|:---|
| **VirusTotal** | 0 malicious, 0 suspicious, 93 harmless. Categorizado como "Information Technology". Certificado SSL autoassinado ("NAT-Server") com validade longa. | A ausência de detecções em scanners tradicionais sugere uma aparência limpa. O certificado autoassinado é um desvio das boas práticas, mas não é um IOC conclusivo por si só. |
| **AlienVault OTX** | **50 pulses** associados. Classificações repetidas como **Phishing, C2, Malware Host**. Associação à família de malware **"NewOrder.doc"** e à técnica MITRE ATT&CK **T1071 (Application Layer Protocol)**. | O volume e a consistência das menções em feeds de ameaças de múltiplas fontes indicam uma **reputação comprometida**. Sugere uso histórico ou contínuo como parte de infraestrutura de ataque, possivelmente como recurso abusado por atores maliciosos. |
| **Consulta DNS (A Record)** | O domínio `qrserver.com` resolve para o endereço IP **`127.0.0.1`** (localhost). | Comportamento **altamente suspeito e atípico** para um domínio público. Forte indicador de atividade maliciosa, associado a configurações de hosts comprometidas, sinkholing, ou testes de malware em ambiente controlado. |
| **cURL / Teste de Conexão** | Falha na conexão HTTP na porta 80 após resolução para `127.0.0.1`. | Corrobora a natureza anômala da resolução DNS. Pode indicar uma configuração projetada para evadir detecção ou falhar silenciosamente em sistemas não comprometidos. |
| **Urlscan.io (Contexto relacionado)** | Subdomínios de `edgeone.app` associados a phishing compartilham o IP `43.174.14.129`. Domínios de vida curta (`sobrinhoneto.com.br`) com padrões de golpe. | Embora não diretamente ligado a `qrserver.com`, ilustra o **modus operandi** de campanhas ativas na região, utilizando infraestrutura de hospedagem barata e ASNs com menor reputação. |
| **Análise de Certificados (crt.sh)** | Histórico extenso e regular de certificados válidos (Let's Encrypt) para `*.qrserver.com` e subdomínios funcionais (`api`, `manage`). | Padrão consistente com uma **infraestrutura legítima e bem mantida** para um serviço web ativo. Este dado contrasta fortemente com os IOCs de DNS e OTX. |
| **Listas de Phishing** | Não listado ativamente no PhishTank ou OpenPhish. | A ausência em listas públicas atuais não descarta o risco identificado por outras fontes, especialmente considerando o histórico da OTX e o IOC de DNS. |

**Conclusão Comportamental:** Existem evidências fortes de que o domínio `qrserver.com` está associado a operações maliciosas.
*   **Reputação Comprometida em Feeds de Inteligência:** A presença massiva em pulses da OTX com classificações específicas de ameaça não é incidental.
*   **Comportamento de DNS Malicioso:** A resolução para `127.0.0.1` é um **IOC técnico forte**, raramente visto em operações legítimas e comumente ligado a malware, phishing ou infraestrutura C2 manipulada.
*   **Potencial para Abuso de Serviço Legítimo:** A infraestrutura técnica aparentemente normal (certificados, subdomínios) pode estar sendo **explorada ou imitada** por atores de ameaças, ou o domínio pode ter sido comprometido no passado.

**Táticas/Procedimentos (MITRE ATT&CK) observados nos pulsos associados:**
- **T1071.001 – Application Layer Protocol: Web Protocols (HTTP/HTTPS)** – Uso potencial para comunicação de C2.
- **T1566 – Phishing** – Associado a múltiplos pulses de phishing.
- **T1583.001 – Acquire Infrastructure: Domains** – O domínio figura como infraestrutura adquirida/abusada em campanhas.

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|:---|:---|
| **Domínio Analisado** | `qrserver.com` |
| **Registrador** | INWX GmbH |
| **Data de Criação** | 2009-08-11 |
| **Status WHOIS** | `clientTransferProhibited` |
| **Servidores de Nome (NS)** | `ns.domrobot.com`, `ns2.domrobot.com`, `ns3.domrobot.com` (Gerenciados pelo registrador) |
| **Resolução DNS Primária (A Record)** | `127.0.0.1` *(IOC Crítico)* |
| **Infraestrutura de Serviço (Subdomínios)** | `api.qrserver.com`, `manage.qrserver.com` (Hospedados na Hetzner, AS24940, Alemanha) |
| **Servidores de E-mail (MX)** | Hospedados no serviço comercial Hornetsecurity. |
| **ASN (para subdomínios de serviço)** | AS24940 (Hetzner Online GmbH) |
| **ISP / Provedor (para subdomínios)** | Hetzner Online GmbH |
| **Localização (para infraestrutura de serviço)** | Alemanha |
| **DNSSEC** | Não assinado. |

## 4. Domínios e IPs Relacionados
- **Subdomínios Funcionais Legítimos (associados à operação do serviço):**
    - `api.qrserver.com`, `api1.qrserver.com`, `api2.qrserver.com`, `manage.qrserver.com`
- **IPs de Infraestrutura Legítima (Hetzner):** Os endereços que hospedam os subdomínios `api` e `manage`.
- **Domínios Maliciosos citados em pulsos da OTX (Contexto de Campanha):** Conforme os pulses analisados, `qrserver.com` é frequentemente listado ao lado de outros IOCs. Uma investigação profunda exigiria a extração da lista completa desses pulses.
- **IP Crítico (IOC):** `127.0.0.1` – Endereço de loopback para o qual o domínio raiz resolve.

## 5. Recomendações de Ações de Investigação
1.  **Investigar a Resolução DNS Anômala:** Prioridade máxima. Verifique em sistemas endpoint (arquivos `hosts`) e em servidores DNS internos se há entradas maliciosas redirecionando `qrserver.com` para `127.0.0.1`. Correlacione com logs de segurança para identificar hosts que possam estar comprometidos.
2.  **Correlacionar com Tráfego de Rede:** Busque em logs de proxy, firewall e DNS por quaisquer tentativas de acesso a `qrserver.com` ou seus subdomínios. Atenção especial para tráfego originado de estações de trabalho, não de servidores.
3.  **Aprofundar a Análise dos Pulses da OTX:** Extraia e analise a lista completa de IOCs (IPs, URLs, hashes) dos **50 pulses** associados a `qrserver.com`. Utilize esses indicadores para buscas proativas (threat hunting) na rede corporativa.
4.  **Avaliação de Risco Contextual:** Determine se o serviço de QR codes é utilizado pela organização. Se não for, considere bloquear o domínio e seus subdomínios em gateways web e via DNS sinkhole.
5.  **Monitoramento Contínuo:** Inscreva o domínio `qrserver.com` para monitoramento em ferramentas de Threat Intelligence, alertando sobre novas detecções ou mudanças de reputação, especialmente em feeds como OTX e VirusTotal.
6.  **Verificar Comprometimento Ativo:** Em sistemas onde o domínio resolve para `127.0.0.1`, realize uma varredura completa por outros indicadores de comprometimento (IOCs) associados às campanhas mencionadas na OTX (ex., malware NewOrder.doc).

## 6. Conclusão
O domínio `qrserver.com` representa um caso de **risco elevado devido a contradições significativas** em sua análise. Enquanto sua infraestrutura técnica e histórico de registro sugerem um serviço legítimo e estabelecido, sua **forte e repetida associação a feeds de ameaças (OTX)** e, mais criticamente, o **comportamento malicioso de resolução DNS para `127.0.0.1`** são indicadores graves de comprometimento ou abuso. A hipótese mais provável é que se trate de um serviço legítimo cuja infraestrutura ou reputação foi cooptada por atores de ameaças para fins maliciosos, como phishing ou C2. Recomenda-se tratá-lo como um **IOC ativo**, implementar as recomendações de investigação e mantê-lo em uma lista de observação e bloqueio preventivo até que as discrepâncias sejam totalmente esclarecidas.