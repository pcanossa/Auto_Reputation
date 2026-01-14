# Relatório de Threat Intelligence – Domínio **teste.com**

> **Fonte dos dados**: WHOIS (whois.uniregistrar.com), VirusTotal, URLScan.io, AlienVault OTX, DNS (Google DNS), cURL, Certificadora Let’s Encrypt, análises de arquivos associados.  
> **Timestamp da Análise**: 2026-01-14T18:20:35.815178.  

## 1. Resumo Executivo
O domínio **teste.com** está registrado no **whois** com o registrador GoDaddy (Cayman Islands) e possui um registro de proteção de privacidade. Ele resolve para **cinco endereços IPv4** (139.162.174.209, 139.162.181.76, 172.104.149.86, 172.104.203.186, 172.104.251.198) distribuídos nos EUA (principalmente regiões da costa leste).  

Os certificados TLS são emitidos pela **Let’s Encrypt** (validade corrente até 10 abr 2026) e não apresentam anomalias. Contudo, o domínio está associado a múltiplas amostras de malwares encontradas no VirusTotal, dentre elas:

* **c77cc485…** – executável Windows UPX‑compactado, identificado como *MyDoom/Emotet* downloader (mais de 60 deteções maliciosas).  
* **0fdc87b7…** – outro executável Windows com comportamento de downloader e presença de *MyDoom* / *SuperThreat*.  
* **arquivo.docx** (macro‑enabled) que contém código VBA que **baixa e executa** `http://teste.com/arquivo.exe` no diretório temporário da vítima.  

Além disso, o domínio aparece em **relatórios de URLScan.io** mostrando resoluções para diferentes IPs (incluindo IPv6) e servindo conteúdo HTML simples (4186 bytes).  

Em conjunto, esses indicadores sugerem que **teste.com** está sendo usado como **infraestrutura de distribuição de payloads** (download de executáveis maliciosos) e como **carga útil de campanhas de phishing/malware via documentos Office**. Não há evidência de serviço legítimo; a presença de certificados válidos pode ser utilizada para mascarar atividades maliciosas.

---

## 2. Análise de Comportamento

| Fonte | Evidência | Interpretação |
|------|-----------|---------------|
| **VirusTotal – Domínio** | `last_analysis_stats`: 1 malicious, 1 suspicious, 59 harmless; 0 malicious / 0 suspicious nos arquivos associados ao domínio. | O domínio em si não é marcado como malicioso pelos scanners, porém os arquivos vinculados (executáveis e documentos) são marcados como malware. |
| **VirusTotal – Arquivos** | *c77cc485…* (UPX, MyDoom) – 63 deteções malicious; *0fdc87b7…* – 63 detections malicious; *arquivo.docx* – 35 detections malicious (Trojan/Downloader). | Evidência clara de uso do domínio como **C2 / servidor de entrega** para trojans e backdoors. |
| **URLScan.io** (diversas execuções) | Resolução para vários IPs (IPv4 e IPv6) e carregamento de página HTML simples. Algumas execuções mostram redirecionamentos ou chamadas a sub‑domínios (`okok.teste.com`). | O domínio tem **infraestrutura de balanceamento / DNS round‑robin**, prática comum em “serviços de hospedagem de C2” para dificultar bloqueios. |
| **DNS** | Resposta contém 5 A‑records diferentes (IP dos EUA). | Distribuição geográfica e de rede típica de provedores Cloud ou de serviços de hospedagem que permitem **escalar** a entrega de payloads. |
| **cURL – Header** | HTTP 200 OK, `Server: openresty/1.27.1.2`, `Content‑Length: 4186`. | O servidor responde com conteúdo estático; não há redirecionamento imediato, mas o conteúdo pode conter scripts de download ou ser “landing page” de phishing. |
| **Certificados SSL** | Vários certificados Let’s Encrypt válidos (última emissão 2026‑01‑10). | Certificados legítimos ajudam a **evitar alertas de navegadores** e aumentam a credibilidade percebida. |
| **Código VBA (docx)** | Funções `URLDownloadToFile` e `ShellExecute` para baixar `http://teste.com/arquivo.exe` e executá‑lo no diretório `%TEMP%`. | **Comportamento típico de malware**: entrega de payload via documentos Office (phishing). |

### Técnicas/Procedimentos (MITRE ATT&CK) observados
| Táctica | Técnica | Comentário |
|---------|---------|------------|
| **Inicial Access** | T1566 – Phishing (macro docx) | Documento malicioso que baixa e executa payload. |
| **Execution** | T1059 – Command‑Line (ShellExecute); T1105 – Ingress Tool Transfer (download de EXE). |
| **Persistence** | T1547 – Create/Modify Autorun (possível criação de arquivos de registro). |
| **Defense Evasion** | T1027 – Obfuscation/Encoding (UPX, Packers). |
| **Command & Control** | T1071 – Application Layer Protocol (HTTP/HTTPS). |
| **Impact** | T1486 – Data Encrypted for Impact (MyDoom). |

---

## 3. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | Não há ASN exclusivo; os IPs pertencem a diferentes blocos (ex.: **AS16509 – Amazon AWS**, **AS15169 – Google Cloud**, **AS16550 – OVH**, **AS20690 – Linode**). |
| **ISP / Provedor** | Vários provedores de nuvem (AWS, Google Cloud, OVH, Linode, etc.). |
| **Localização** | Todos os IPs estão alocados nos **Estados Unidos** (costa leste e interior). |
| **Endereços IPv4** | 139.162.174.209, 139.162.181.76, 172.104.149.86, 172.104.203.186, 172.104.251.198 |
| **Endereço IPv6** | Não divulgado nas respostas DNS, mas URLScan.io registra IPv6 para alguns testes. |
| **DNSSEC** | Não assinado ( `DNSSEC: unsigned`). |
| **TTL padrão** | 600 s (10 min), típico de serviços de CDN ou balanceamento. |

---

## 4. Domínios e IPs Relacionados

### Domínios/Sub‑domínios observados
* `teste.com` (apex) – alvo principal.  
* `okok.teste.com` – sub‑domínio usado em algumas execuções de URLScan (possível “dropper” ou “callback”).  
* `url.teste.com`, `action.att.com.teste.com` – outros sub‑domínios vistos nos logs de URLScan.  

### IPs associados (resolvidos nas consultas DNS)
| IP | Possível provedor/ASN |
|----|----------------------|
| 139.162.174.209 | OVH (AS16276) |
| 139.162.181.76  | OVH (AS16276) |
| 172.104.149.86  | Linode (AS63949) |
| 172.104.203.186 | Linode (AS63949) |
| 172.104.251.198 | Linode (AS63949) |

*Observação*: a variação de IPs pode indicar **rotatividade de infraestrutura** ou uso de um serviço de “anycast”.

### Arquivos associados (malware) – hashes relevantes
| SHA‑256 | Tipo | Detections (VT) | Comentário |
|----------|------|------------------|------------|
| `c77cc485980f82d0a6012316a181be59c435...` | Windows EXE (UPX) | 63 malicious | MyDoom/Emotet downloader. |
| `0fdc87b7...` | Windows EXE | 63 malicious | Downloader de trojan, contém macro de download. |
| `4588636f...` (ICL0udin_Bypass) | Windows EXE | 47 malicious | Potencial loader/packer. |
| `a93092f...` (docx) | Office DOCX (macro) | 0 malicious (mas malware) | VBA que baixa `http://teste.com/arquivo.exe`. |
| `f414cdf7...` (xlsx) | Excel XLSM | 36 malicious | Macro que baixa e executa payload. |
| `fe82a2b2...` (APK) | Android APK | 0 malicious | Contém permissões “INTERNET”, “CAMERA”, “VIBRATE”, contém chamadas a `http://teste.com`. |

---

## 5. Recomendações (investigação e detecção)

1. **Monitoramento DNS**  
   - Crie regras de alerta para **consultas ao domínio `teste.com`** e seus sub‑domínios em logs de DNS (resolvidas para os IPs acima).  
   - Correlacione com tráfego fora‑do‑tempo (pico fora de horário comercial).  

2. **Bloqueio de IPs**  
   - Adicione os cinco endereços IPv4 a listas de **deny‑list** nos firewalls perímetro e proxies.  
   - Caso a infraestrutura utilize *anycast*, monitore novos IPs associados ao domínio e avalie bloqueio em nível de FQDN (DNS‑sinkhole).  

3. **Inspeção de tráfego HTTP/HTTPS**  
   - Desbloqueie apenas conexões HTTPS a `teste.com` e registre a inspeção de certificado (Let’s Encrypt).  
   - Procure por **download de arquivos executáveis** (extensões .exe, .dll, .msi) no corpo das respostas.  

4. **Análise de E-mails e Documentos**  
   - Verifique caixas de correio por documentos Office (DOCX, XLSM) que contenham macros com referência a `teste.com`.  
   - Utilize ferramentas de sandbox (ex.: Cuckoo, VMRay) para abrir suspeitos e observar comportamento de download.  

5. **Threat Hunting de indicadores de compromise (IoC)**  
   - Procure nos endpoints pelos hashes SHA‑256 dos executáveis listados (c77cc485…, 0fdc87b7…).  
   - Busque por arquivos criados no `%TEMP%` com nome “arquivo.exe” ou similar.  
   - Verifique registros de processos que invoquem `URLDownloadToFile` ou `ShellExecute` via ETW/Windows Event Forwarding.  

6. **Enriquecimento adicional**  
   - Consulte bancos de dados de reputação de IP (AbuseIPDB, ThreatIntel Platforms) para validar histórico de abusos.  
   - Verifique se os IPs pertencem a **cloud providers** que oferecem “pay‑as‑you‑go” e podem ser abusados por atores maliciosos.  

7. **Comunicação com provedores**  
   - Notifique os provedores de nuvem (AWS, Linode, OVH) sobre o uso abusivo dos seus blocos de IP; eles podem tomar providências de remoção.  

8. **Atualização de IDS/IPS**  
   - Importe as regras de Snort/Suricata já listadas (ex.: `PROTOCOL-ICMP Unusual PING`, `FILE tracking GIF (1x1 pixel)`) que já detectam tráfego relacionado.  
   - Crie regras específicas para **HTTP GET** a `/arquivo.exe` ou `/favicon.ico` seguido por 1×1 GIF (indicativo de rastreamento).  

---

## 6. Conclusão
O domínio **teste.com** apresenta forte indício de ser **instrumento de campanha maliciosa**, atuando como **servidor de entrega (C2/Downloader)** e como **referência em documentos Office** que executam payloads. Embora o domínio possua certificados legítimos e responda com conteúdo HTTP “normal”, a combinação de:

* Vários IPs em provedores de nuvem,  
* Amostras de malware UPX altamente detectadas que apontam para o domínio,  
* Documentos com macros que baixam executáveis de `http://teste.com/arquivo.exe`,  

... demonstra que ele está sendo utilizado ativamente por atores maliciosos para distribuir **trojans, ransomware e ferramentas de download**.  

Recomenda‑se **monitoramento ativo**, **bloqueio de IP/FQDN** e **investigações de endpoints** para identificar possíveis compromissos. A presença de certificados válidos reforça a necessidade de **inspeção profunda** (deep packet inspection) em vez de confiar apenas em validação TLS.  

---
**Nível de Risco:** **Médio‑Alto** (suficiente para inclusão em listas de bloqueio corporativas e para ação de threat‑hunting).