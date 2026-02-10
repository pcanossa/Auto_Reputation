# Relatório de Threat Intelligence – Domínio **sistemafull.site**

> **Fonte dos dados**: WHOIS (via VirusTotal), VirusTotal, Urlscan.io, DNSDumpster, Phishing Army, AlienVault OTX.  
> **Timestamp da Análise**: 2026-02-10T12:02:37.676255.

## 1. Resumo Executivo
O domínio `sistemafull.site` está registrado na GoDaddy e utiliza serviços de DNS da Cloudflare. Apesar de não possuir detecções diretas como malicioso (0 detecções no VirusTotal) e não estar presente em Pulses públicos do AlienVault OTX, ele está **operacionalmente vinculado a uma campanha ativa de phishing**. Análises do Urlscan.io mostram que ele é frequentemente escaneado em conjunto com uma série de domínios fraudulentos que simulam portais da Receita Federal do Brasil (ex.: `portalbrofcbenef.com`, `consultabenecbrs.com`). Sua infraestrutura é distribuída, com subdomínios apontando para servidores em múltiplos países (EUA, Brasil, França) e ASNs variados, um padrão comum em operações maliciosas para resiliência. O servidor principal não responde a requisições HTTP, possivelmente como medida de ofuscação.

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|------|------------|---------------|
| **VirusTotal** | 0 malicious, 0 suspicious, 60 harmless. Reputação neutra (0). Sem arquivos comunicados ou comentários da comunidade. | Nenhum scanner tradicional sinaliza o domínio como malicioso no momento da análise. Isso não descarta seu uso em campanhas evasivas ou como infraestrutura de suporte. |
| **Urlscan.io** | Aparece em múltiplos scans de outros domínios de phishing brasileiros (ex.: `portalbrofcbenef.com`, `consultabenecbrs.com`). A tag `@phish_report` está presente em scans de domínios relacionados. | Forte **correlação contextual com uma campanha de phishing ativa** que visa roubar dados pessoais (CPF) sob o pretexto de serviços da Receita Federal. O domínio `sistemafull.site` pode estar na mesma infraestrutura ou ser um ponto de teste/controle. |
| **AlienVault OTX** | Lista de Pulses vazia. | Não há menção pública em feeds de inteligência de ameaças consolidados. |
| **DNS / HTTP** | Resolução DNS ativa para `95.111.233.242`. Tentativa de conexão HTTP na porta 80 resulta em **timeout** após 21 segundos. | Comportamento anômalo para um servidor web. Pode estar configurado para não responder a escaneamentos automáticos ou estar inativo/sob controle de acesso. |
| **Certificados SSL/TLS** | Múltiplos certificados válidos para o domínio e subdomínios, emitidos por Let's Encrypt, GoDaddy e Cloudflare. Incluem subdomínios como `api.`, `base1.`, `base2.`, `bad.`, `nada.`. | Infraestrutura ativa e em desenvolvimento. A rápida rotatividade e variedade de emissores podem indicar testes ou uso de serviços automatizados. |
| **Phishing Army** | Ausente na lista. | Não está listado em feeds de phishing mais amplos no momento. |

**Táticas/Procedimentos (ATT&CK) observados nos domínios relacionados:**
- **T1583.001 - Acquire Infrastructure: Domains** – Registro de múltiplos domínios com nomes semelhantes a serviços legítimos.
- **T1566.002 - Phishing: Spearphishing Link** – Uso de links em páginas de phishing que imitam portal governamental.
- **T1595.001 - Active Scanning: Scanning IP Blocks** – Possível uso de escaneamento para encontrar hosts vulneráveis (baseado em subdomínios como `bad.`, `nada.`).

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **Domínio Analisado** | sistemafull.site |
| **IP Principal (A Record)** | 95.111.233.242 (não foi possível determinar ASN/ISP deste IP específico a partir dos dados fornecidos) |
| **Nameservers** | `norman.ns.cloudflare.com`, `roxy.ns.cloudflare.com` (Cloudflare) |
| **Registrador** | GoDaddy |
| **Data de Criação** | 2025-06-04 |
| **Subdomínios e Infraestrutura (via DNSDumpster)** | |
| **api.sistemafull.site** | IP: 107.152.39.157 - AS11878 (TZULO - tzulo, inc.) - País: **EUA** |
| **base1.sistemafull.site** | IP: 144.22.131.66 - AS31898 (ORACLE-BMC-31898) - País: **Brasil** |
| **base2.sistemafull.site** | IP: 144.22.219.174 - AS31898 (ORACLE-BMC-31898) - País: **Brasil** |
| **nada.sistemafull.site** | IP: 161.97.127.105 - AS51167 (CONTABO, DE) - País: **França** |

## 4. Domínios e IPs Relacionados
- **Domínios de Phishing Correlacionados (Urlscan.io):** `portalbrofcbenef.com`, `consultabenecbrs.com`, `portalbenefibr.com`, `consulta.benecbrs.site`, `oficial.consultarabrof.online`. Todos compartilham o padrão de URL `/site-receita/consulta.html?cpf=`.
- **IPs de Hospedagem dos Domínios de Phishing:** `216.238.103.54`, `151.243.137.170`, `151.243.137.191`, `192.250.227.149`, `216.238.112.194`.
- **Subdomínios e IPs da Infraestrutura `sistemafull.site`:** Listados na seção 3.

## 5. Recomendações de Ações de Investigação
1.  **Correlação em Logs Internos:** Busque por tráfego de rede (DNS, HTTP/HTTPS) para o domínio `sistemafull.site` e todos os seus subdomínios listados, bem como para os domínios de phishing correlacionados.
2.  **Análise de Certificados:** Monitore a emissão de novos certificados SSL para os subdomínios de `sistemafull.site`, pois podem indicar a ativação de novos nós de infraestrutura.
3.  **Threat Hunting por Artefatos:** Procure em endpoints e logs de e-mail por referências aos domínios de phishing listados, especialmente em URLs contendo a string `/site-receita/`.
4.  **Enriquecimento de Indicadores:** Submeta os IPs `95.111.233.242`, `107.152.39.157`, `144.22.131.66`, `144.22.219.174` e `161.97.127.105` a ferramentas de reputação de IP (ex.: AbuseIPDB, GreyNoise) para verificar histórico de abuso.
5.  **Monitoramento de Nova Registro de Domínios:** Configure alertas para o registro de novos domínios contendo strings como `"benef"`, `"consulta"`, `"receita"`, `"cbrs"`, `"brof"`, combinados com TLDs comuns.

## 6. Conclusão
O domínio `sistemafull.site` apresenta um **perfil de alto risco indireto**. Embora não seja detectado como malicioso por ferramentas estáticas, suas fortes associações operacionais com uma campanha ativa de phishing contra cidadãos brasileiros, somadas a uma infraestrutura distribuída e com comportamento de rede anômalo, indicam que ele provavelmente faz parte de um ecossistema malicioso. Recomenda-se tratá-lo como um **Indicador de Comprometimento (IoC)** e incluí-lo, juntamente com todos os domínios e IPs relacionados, em listas de bloqueio e monitoramento contínuo.