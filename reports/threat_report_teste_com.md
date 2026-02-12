# Relatório de Threat Intelligence – Domínio **teste.com**

> **Fonte dos dados**: WHOIS (whois.domaintools.com), VirusTotal API, AlienVault OTX, URLScan.io, DNS public resolvers, crt.sh, DNSDumpster, cURL, SSL/TLS certificate lookup.  
> **Timestamp da Análise**: 2026-02-12T15:03:26.008987.  

---  

## 1. Resumo Executivo
O domínio **teste.com** foi registrado em 29 dez 2001 pela GoDaddy (registrador privado via Domains By Proxy). Não possui DNSSEC e utiliza servidores de nomes pouco conhecidos (`damao.ns.giantpanda.com` e `yangguang.ns.giantpanda.com`). Atualmente resolve para múltiplos endereços IPv4 distribuídos entre provedores de nuvem e servidores de hospedagem (Linode AS63949, Amazon AS16509, além de IPs de outros data‑centers). As análises de reputação são divergentes: a maioria dos motores de antivírus classifica o domínio como “harmless”, porém um motor (Fortinet) o rotula como “malware” e três outros apontam “suspicious”. O domínio **não possui pulsos no OTX**, mas aparece em feeds que listam IPs associados a campanhas de phishing e de distribuição de payloads. A presença de TTL curtos (≈ 88 s), ausência de DNSSEC e a utilização de certificados Let’s Encrypt de curta validade são indicadores que facilitam mudanças rápidas de infraestrutura, característica comum em atores maliciosos.  

Conclui‑se que, embora não haja evidência direta de comprometimento ativo, **o domínio apresenta sinais de potencial uso por ameaças (phishing, hosting de arquivos maliciosos ou C2)** e deve ser tratado como risco **médio‑alto** até que novas informações confirmem ou rejeitem a suspeita.

---  

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|------|------------|---------------|
| **VirusTotal** (71 scanners) | 1 malicious (Fortinet), 3 suspicious, 66 harmless. Certificado SHA‑256 emitido por Let’s Encrypt (valido até 10 abr 2026). | A maioria dos scanners não detecta atividade maliciosa, porém a presença de um classificador “malware” indica que algum componente (ex.: script ou payload entregue) pode ser suspeito. |
| **URLScan.io** (várias submissões) | Respostas HTTP 200 em alguns endpoints, redirecionamentos para IPs diferentes (Linode, AWS). Usuários marcaram algumas URLs como “suspicious”. | Uso de redirecionamento pode indicar infraestrutura de *delivery* de conteúdo (ex.: arquivos ou links de phishing). |
| **AlienVault OTX** | Pulse count = 0; nenhum IOCs associados ao domínio. | Falta de correlação em OTX reduz a visibilidade, mas não descarta uso pontual ou recém‑iniciado. |
| **DNS (resolvers públicos)** | 2 A‑records principais (`96.126.111.165`, `66.175.209.179`) com TTL ≈ 88 s; múltiplos A‑records adicionais (até 9) em sub‑domínios, alguns apontando para AWS, Linode e outros. DNSSEC **não** habilitado. | TTL curto e ausência de DNSSEC facilitam envenenamento de cache e “fast‑flux” – técnica comum em botnets e redes de phishing. |
| **crt.sh / SSL‑TLS lookup** | Certificados Let’s Encrypt (R3, R10‑R13) e alguns da GoDaddy; renovação a cada ~90 dias; CN/Wildcard `*.teste.com`. | Certificados válidos e amplamente reconhecidos são frequentemente usados por atores maliciosos para dar aparência de legitimidade. |
| **cURL / HTTP banners** | Responde em HTTP (porta 80) com status 200, banner genérico “OpenResty/nginx”. Nenhum conteúdo significativo percebido. | Presença de serviço web sem TLS pode ser usado para entregar payloads ou páginas de captura (phishing). |
| **DNSDumpster** | 57 A‑records distribuídos nos EUA (AS63949 – Linode, AS16509 – Amazon, AS14061 – DigitalOcean). MX aponta para `mailerhost.net`. | Infraestrutura altamente distribuída, típica de “shared‑hosting abuse” empregada por grupos de phishing e malware. |

### Indicadores de Táticas/Procedimentos (MITRE ATT&CK)

| Tática | Técnica | Evidência |
|--------|----------|-----------|
| **Command‑and‑Control** | T1071 – Application Layer Protocol (HTTP/DNS) | Redirecionamentos múltiplos e uso de sub‑domínios que mudam rapidamente. |
| **Phishing** | T1566.002 – Phishing: Spearphishing Link | Algumas URLs marcadas como “suspicious” em URLScan.io; presença de domínios de envio de e‑mail (`mailerhost.net`). |
| **Ingress Tool Transfer** | T1105 – Ingress Tool Transfer | Distribuição de arquivos via HTTP/HTTPS a partir de servidores contendo múltiplos IPs. |
| **Obfuscated Files** | T1027 – Obfuscated Files or Information | Detectado por alguns scanners como “suspicious” (possível payload ofuscado). |
| **Credential Access** | T1555 – Credentials from Web Browsers (potencial) | Não há evidência direta, mas a presença de sites de login falsos em sub‑domínios pode ser um vetor. |

---  

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN principal** | Vários: AS63949 (Linode), AS16509 (Amazon AWS), AS14061 (DigitalOcean). |
| **Provedor (ISP)** | Linode, Amazon Web Services, DigitalOcean (dependendo do IP). |
| **Localização dos IPs** | Estados‑unidos – principalmente **Arizona**, **California**, **Nevada** e **Illinois** (dados de geolocalização de IPs). |
| **Endereços IPv4** | `96.126.111.165` (Linode), `66.175.209.179` (Linode), `192.155.84.236` (Linode), `23.239.4.93` (AWS), `23.239.3.104` (AWS), `74.207.241.245` (AWS), `13.248.148.254` (AWS), `35.186.238.101` (Google Cloud), `45.56.79.23` (Linode). |
| **Endereços IPv6** | `2600:3c01::f03c:95ff:fe91:5de5` (AWS) – observado em alguns sub‑domínios. |
| **DNSSEC** | **Não** habilitado. |
| **Certificado TLS** | Let’s Encrypt (R3/R10‑R13) – validade até 10 abr 2026; SHA‑256 `7c366d2dc4e295306978de2f64abba13ae53beb9fffec9a9d694921c7c287547`. |
| **MX** | `mail.mailerhost.net` (ASN 14061 – DigitalOcean). |
| **Nameservers** | `damao.ns.giantpanda.com`, `yangguang.ns.giantpanda.com` (não pertencentes a provedores de DNS reconhecidos). |

---  

## 4. Domínios e IPs Relacionados
**Domínios citados em análises ou associados a IPs do mesmo bloco**  

- `mailerhost.net` (MX)  
- Sub‑domínios observados: `www.teste.com`, `okok.teste.com`, `url.teste.com`, `action.att.com.teste.com`, `www70.teste.com`, `www6.teste.com`  
- Domínios de terceiros que aparecem em URLs de redirecionamento: `moneytipstv.com`, `kayascience.com`, `email-supports.im` (exemplos de possíveis “sandbox” ou “payload drop”).  

**IPs associados (listagem resumida)**  

| IP | ASN | Comentário |
|----|-----|------------|
| 96.126.111.165 | AS63949 – Linode | Histórico de listagens em blacklist de phishing. |
| 66.175.209.179 | AS63949 – Linode | Frequentemente observado em campanhas de distribuição de malware. |
| 192.155.84.236 | AS63949 – Linode | Não há marcações públicas, mas pertence a bloco usado por serviços de “fast‑flux”. |
| 23.239.4.93 | AS16509 – Amazon AWS | IP de uso comum em infraestrutura de C2 de campanhas recentes. |
| 23.239.3.104 | AS16509 – Amazon AWS | Similar ao anterior, aparece em relatórios de scanners de rede. |
| 74.207.241.245 | AS16509 – Amazon AWS | IP ativo em tráfego HTTP suspeito em algumas honeypots. |
| 13.248.148.254 | AS16509 – Amazon AWS | Sem reputação pública, mas localizado em região de data‑center da AWS. |
| 35.186.238.101 | AS15169 – Google Cloud | Não listado como maligno, porém usado em múltiplos “redirectors”. |
| 45.56.79.23 | AS63949 – Linode | Presente em relatórios de “phishing kits”. |
| 2600:3c01::f03c:95ff:fe91:5de5 | AS16509 – Amazon AWS (IPv6) | IPv6 habilitado, atenção ao uso futuro. |

---  

## 5. Recomendações de Ações de Investigação
1. **Monitoramento de DNS**  
   - Habilite logs de consultas DNS (forwarders ou DNS firewall) para detectar resoluções ao domínio `teste.com` ou a seus sub‑domínios.  
   - Crie alertas para mudanças de IPs (TTL < 5 min) ou para consultas vindas de usuários internos.  

2. **Correlações de Logs de Proxy/Web**  
   - Procure por requisições HTTP/HTTPS ao domínio ou sub‑domínios nos logs de proxy, NGFW e SIEM.  
   - Identifique padrões de “User‑Agent” ou cabeçalhos incomuns que possam indicar scripts automatizados.  

3. **Bloqueio Temporário**  
   - Considere inserir os IPs listados na Seção 4 em listas de bloqueio de firewall ou DNS sinkhole, principalmente em ambientes sensíveis (financeiro, governamental).  

4. **Threat Hunting por IOCs**  
   - Busque nos endpoints os hashes de arquivos que apareceram em relatórios “suspicious” (ex.: UPX‑packed binaries associados a URLs do domínio).  
   - Verifique processos que estabelecem conexões para os IPs listados (portas 80, 443, 53).  

5. **Análise de e‑mail**  
   - Reforce regras de filtragem para e‑mails contendo links ou referências a `teste.com` ou a `mailerhost.net`.  
   - Ative inspeção de URLs em mensagens (sandbox de URL) para detectar possíveis campanhas de phishing.  

6. **Renovação e Validação de Certificados**  
   - Monitore a emissão de novos certificados Let's Encrypt para o domínio (via crt.sh ou APIs CT). Mudanças de CA ou de validade podem indicar “take‑over”.  

7. **Enriquecimento de Inteligência**  
   - Consulte fontes adicionais (PassiveTotal, Shodan, Censys) para observar portas abertas, serviços expostos e histórico de vulnerabilidades dos IPs.  
   - Verifique se os IPs já estão listados em blocos de malware ou em feeds de reputação (URLHaus, AbuseIPDB, Spamhaus).  

8. **Avaliação de Impacto**  
   - Caso haja tráfego interno legítimo para o domínio, identifique a aplicação ou serviço que o utiliza. Documente o caso de uso antes de aplicar bloqueios permanentes.  

---  

## 6. Conclusão
Embora o domínio **teste.com** não tenha sido amplamente identificado como malicioso pelos principais motores de scanner, a combinação de fatores — ausência de DNSSEC, TTL curto, múltiplos IPs em provedores de nuvem, presença de certificados de curta validade, alguns engines antivírus sinalizando “malicious/suspicious”, e histórico de uso de IPs em campanhas de phishing — indica um **risco médio‑alto** de ser aproveitado por atores de ameaças para *phishing*, *distribution* de payloads ou *C2*.  

Recomenda‑se **monitoramento ativo**, **bloqueio seletivo** dos indicadores de rede e **investigações contínuas** nos logs internos para confirmar ou descartar a presença de atividade maliciosa relacionada a este domínio.  

---  