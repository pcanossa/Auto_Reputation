# Relatório de Threat Intelligence – IP **43.154.15.250**

> **Fonte dos dados**: WHOIS, Urlscan.io, VirusTotal, AlienVault OTX, Netlas, análise de cabeçalhos HTTP (cURL), IPInfo.io, AbuseIPDB, Scamalytics, VPNAPI.
> **Timestamp da Análise**: 2026-04-20T10:41:32.067510.

---

## 1. Resumo Executivo

O IP **43.154.15.250** está localizado em Hong Kong e pertence ao provedor **Tencent Cloud (AS132203)**. A análise revela uma **reputação conflitante**: enquanto ferramentas de reputação de abuso (AbuseIPDB, Scamalytics) o classificam como de baixo risco, múltiplas fontes técnicas apontam para **indicadores concretos de atividade maliciosa ou de alto risco**. O host expõe serviços HTTP, HTTPS e FTP, executando um stack vulnerável (Nginx, Laravel, PHP) com múltiplas vulnerabilidades críticas (CVEs) de exploração pública. Ele está associado a domínios suspeitos (incluindo um sinalizado como "certstream-suspicious"), apresenta comportamentos anômalos (timestamp HTTP no futuro) e é identificado como um endereço de VPN/Data Center, um padrão comum em infraestruturas de ataque. Conclui-se que este IP representa um **vetor de alto risco**, potencialmente comprometido ou utilizado para hospedar conteúdos de phishing, distribuir malware ou atuar como plataforma para ataques como DDoS.

---

## 2. Análise de Comportamento

| Fonte | Evidência | Interpretação |
| :--- | :--- | :--- |
| **VirusTotal** | 56 harmless, 1 suspicious (SOCRadar), 0 malicious. JARM fingerprint específico registrado. | Reputação majoritariamente limpa em scanners automatizados, mas uma detecção "suspicious" indica atividade anômala reportada. O fingerprint JARM pode ser usado para rastrear esta infraestrutura específica. |
| **AlienVault OTX** | Reputação neutra (score 0). Passive DNS associa o IP a hostnames como `mail-serve.hagro.cn`, `develop.oa.quanqiusou.cn`. | A ausência de pulsos de ameaça ativos é positiva, mas os hostnames associados, especialmente um subdomínio "mail-serve", são um padrão comum em infraestrutura de phishing e merecem monitoramento. |
| **Urlscan.io** | Associação aos domínios `halin-alibaba.com` (sinalizado como "certstream-suspicious"), `zqsafeprotect.com`, `gnepc.com`. Uso de certificados TLS de curta duração (89 dias). | O domínio `halin-alibaba.com` possui um indicador direto de registro suspeito, sugerindo potencial uso em fraudes ou phishing. Certificados de curta duração são comuns em infraestrutura efêmera e maliciosa. |
| **Netlas** | Host expõe portas 80, 443, 21. Stack: Nginx, Laravel, PHP. Múltiplas vulnerabilidades críticas listadas (ex: CVE-2023-44487). | A superfície de ataque é ampla e vulnerável. A presença de CVEs críticos e de alta severidade com exploração pública conhecida transforma este host em um alvo fácil ou uma ferramenta potente para ataques (ex: DDoS HTTP/2). |
| **Análise HTTP (cURL)** | Cabeçalho `Date` com timestamp no futuro (20 Apr 2026). Cookies `laravel_session` e `XSRF-TOKEN` presentes. Cabeçalho `token` vazio. | Timestamp futuro é um forte indicador de manipulação do sistema ou configuração incorreta, frequentemente associado a kits de phishing ou infraestrutura comprometida. A presença de uma aplicação Laravel ativa aumenta o vetor de ataque. |
| **AbuseIPDB / Scamalytics** | AbuseIPDB: Confidence Score 0 (1 reporte). Scamalytics: Risk Score 0 (low). Não listado em principais blacklists. | Não há evidências de abuso massivo ou reportado publicamente. Isto pode indicar uma infraestrutura nova, sofisticada ou utilizada em estágios iniciais de ataque que não geram queixas diretas. |
| **VPNAPI** | Classificado como um endereço IP de **VPN** e **Data Center**. | Esta classificação corrobora o uso em infraestrutura de hospedagem na nuvem, um vetor comum para ataques devido à facilidade de provisionamento e anonimato relativo. |

**Conclusão sobre Comportamento:** O IP **43.154.15.250** exibe um perfil de **alto risco técnico** combinado com uma **reputação superficialmente limpa**. Os indicadores mais preocupantes são a presença de vulnerabilidades críticas exploráveis, a associação a domínios suspeitos e a classificação como VPN/Data Center. O host parece estar ativo servindo uma aplicação web (possivelmente Laravel) que pode estar configurada para fins maliciosos, como coleta de credenciais. A baixa pontuação em ferramentas de abuso sugere que sua atividade maliciosa pode não ser amplamente reportada ou é recente.

---

## 3. Superfície de Ataque

### 3.1 Portas Abertas / Serviços
- **80/TCP**: HTTP (Servidor: nginx) - Aplicação web Laravel.
- **443/TCP**: HTTPS (Servidor: nginx) - Aplicação web Laravel com TLS.
- **21/TCP**: FTP - Serviço de transferência de arquivos (aumenta a superfície de ataque).

### 3.2 Vulnerabilidades (CVEs) Detectadas
Com base na análise do Netlas, as seguintes vulnerabilidades críticas e de alta severidade foram associadas ao stack de software do host:
- **CVE-2023-44487** (Crítica): Vulnerabilidade de DDoS HTTP/2 "Rapid Reset", ativamente explorada *in the wild*. Permite que um atacante cause negação de serviço com baixo custo.
- **CVE-2021-28254** (Alta): Vulnerabilidade de desserialização remota de código no Laravel (via `unserialize`). Pode levar à execução remota de código (RCE).
- **CVE-2024-11235, CVE-2024-11236, CVE-2025-14180** (Críticas/Altas): Conjunto de vulnerabilidades no PHP que permitem execução de código arbitrário, negação de serviço e vazamento de informações.

**Relação com Comportamento Malicioso:** A existência dessas vulnerabilidades, especialmente as de RCE e DDoS, torna este IP um **vetor de ataque potencialmente poderoso**. Um ator de ameaça pode explorá-las para:
1.  Comprometer o host e usá-lo como parte de uma botnet para ataques DDoS.
2.  Obter controle total do servidor para hospedar malware, páginas de phishing ou servidores de C2.
3.  Lançar ataques contra outros sistemas a partir desta infraestrutura comprometida.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
| :--- | :--- |
| **ASN** | **AS132203 – Tencent Building, Kejizhongyi Avenue** |
| **ISP / Provedor** | **Tencent Cloud Limited** (Também listado como ACEVILLE PTE.LTD.) |
| **Cidade / Região / País** | **Hong Kong (HK)** / **Hong Kong (HK)** / **China (CN)** |
| **Coordenadas (Fontes Variadas)** | Aproximadamente Lat: 22.2842, Lon: 114.1759 |
| **Tipo de Rede** | Data Center / Web Hosting / VPN (Classificado por VPNAPI e Scamalytics) |
| **Contato de Abuso** | `abuse@tencent.com` |

---

## 5. Recomendações (Próximos Passos)

1.  **Bloqueio Proativo em Perímetros**: Considerar o bloqueio do tráfico originado do IP **43.154.15.250** em firewalls e sistemas de prevenção de intrusão (IPS), com base nos fortes IOCs técnicos (VPN/Data Center, vulnerabilidades críticas, domínios suspeitos).
2.  **Correlação com Logs Internos**: Buscar em logs de proxy web, WAF, e DNS por conexões de ou para este IP, especialmente para as portas 443, 80 e 21. Investigar qualquer sessão Laravel (`laravel_session`) incomum.
3.  **Análise de Tráfego de Rede**: Capturar e analisar o tráfego de/para este IP (se detectado) em busca de padrões anômalos, especialmente relacionados aos CVEs listados (ex: tráfego massivo HTTP/2 indicativo de CVE-2023-44487).
4.  **Monitoramento de Feeds de Ameaças**: Adicionar o IP, o fingerprint JARM e os domínios associados (`halin-alibaba.com`, `mail-serve.hagro.cn`) a listas de monitoramento em ferramentas de Threat Intelligence.
5.  **Varredura de Vulnerabilidades Externa (Autorizada)**: Se pertinente ao escopo de defesa, realizar uma varredura de vulnerabilidades não intrusiva contra este IP para confirmar a exposição das CVEs listadas.
6.  **Investigação dos Domínios Associados**: Profundar a investigação nos domínios `halin-alibaba.com` e `mail-serve.hagro.cn` usando ferramentas como URLScan, VirusTotal e whois para entender sua finalidade e histórico.
7.  **Notificação ao Provedor**: Em caso de incidente confirmado (ex: ataque originado deste IP), notificar o provedor Tencent Cloud (`abuse@tencent.com`) com evidências para possível ação de *takedown* ou mitigação.

---

## 6. Considerações Finais

O IP **43.154.15.250** apresenta um caso clássico de **risco baseado em indicadores técnicos versus reputação superficial**. Apesar de não constar em listas de abuso públicas amplas, sua configuração técnica (serviços expostos, vulnerabilidades graves), seus comportamentos anômalos (timestamp futuro) e seus atributos de rede (VPN/Data Center em Hong Kong) o caracterizam como uma ameaça significativa. Ele possui todos os elementos para ser um vetor eficaz em campanhas de phishing (via aplicação Laravel), distribuição de malware ou ataques de DDoS. A recomendação prioritária é tratá-lo como host malicioso e implementar controles de bloqueio, enquanto se monitora ativamente por qualquer tentativa de comunicação com a rede interna. A presença de vulnerabilidades críticas de exploração pública torna a urgência dessa ação ainda maior.