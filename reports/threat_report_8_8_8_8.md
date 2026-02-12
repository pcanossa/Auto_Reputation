# Relatório de Threat Intelligence – IP **216.252.199.59**

> **Fonte dos dados**: Shodan, VirusTotal, AlienVault OTX, AbuseIPDB, IPInfo.io, RDAP/ARIN, Scamalytics.  
> **Timestamp da Análise**: 2026-02-12T15:06:29.347714.  

---

## 1. Resumo Executivo
O endereço **216.252.199.59** está alocado em **Blacksburg, Virginia, EUA**, sob o ASN **AS31827 – Biz Net Technologies**. Não foram encontradas portas abertas nos scans públicos do Shodan e o serviço HTTP simplesmente timeout, indicando que o host não expõe serviços de rede usuais ou está protegido por firewall. Apesar da aparente “limpeza” de reputação em bases como AbuseIPDB e Scamalytics, há **indícios de atividade maliciosa**: um motor de análise do VirusTotal (SOCRadar) classificou o IP como **malicioso** e múltiplos *pulses* do AlienVault OTX o vinculam a campanhas de **phishing financeiro**, **botnet Qakbot** e possíveis infraestruturas de **comando e controle (C2)**. Assim, embora não haja serviços expostos, o IP pode estar operando como cliente/bot ou relay em ataques direcionados.

---

## 2. Análise de Comportamento

| Fonte | Evidência | Interpretação |
|------|-----------|---------------|
| **VirusTotal** | 60 harmless, 1 malicious (SOCRadar), 32 undetected | Predominância de resultados “clean”, mas a presença de **1 detecção maliciosa** indica que o IP já esteve associado a atividade suspeita. |
| **AlienVault OTX** | Vários *pulses* ligando o IP a **Qakbot**, **phishing ao IRS**, **DDoS**, **TLS‑handshake suspeito** | Fortes indícios de uso em **botnet** e **campanhas de fraude financeira**; pode atuar como C2 ou relay. |
| **Shodan** | Nenhuma porta reportada (404 “No information available”). | Host possivelmente “stealth”, sem serviços públicos ou com firewall restritivo. |
| **AbuseIPDB / Scamalytics** | Score 0, não listado em blacklist, não é proxy/VPN/TOR. | Ausência de denúncias públicas, mas isso pode refletir a natureza “low‑profile” da atividade. |
| **RDAP / WHOIS** | Registrado para **Biz Net Technologies**, contato em Blacksburg (2200 Kraft Dr., Suite 2250). | Provedor legítimo de data‑center/ISP; o IP pode ser de cliente interno ou de um serviço hospedado. |
| **GeoIP (IPInfo.io)** | Latitude 37.2296, Longitude ‑80.4139 | Confirma a localização nos EUA. |

**Conclusão de comportamento:**  
O conjunto de sinais aponta para **possível envolvimento em infraestruturas maliciosas** (botnet, phishing/C2), ainda que o host não exponha portas abertas. A falta de denúncias massivas pode indicar que o IP está sendo usado em etapas de ataque que não geram tráfego visível (ex.: comunicação interna, tunneling, ou como ponto de apoio temporário).  

---

## 3. Superfície de Ataque

### 3.1 Portas abertas / Serviços
- **Nenhuma porta aberta** foi detectada pelo Shodan (resultado 404).  
- Teste de conexão HTTP (porta 80) resultou em *timeout*, sugerindo filtro de firewall ou ausência de serviço web.  

> **Observação:** A ausência de portas visíveis não elimina risco; o host pode operar em portas não‑padrão, dentro de VPNs ou responder apenas a tráfego autorizado.

### 3.2 Vulnerabilidades (CVEs) identificadas
- **Nenhuma CVE** foi listada nas fontes consultadas, pois não há serviços públicos identificados.  

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|------|-------|
| **ASN** | **AS31827 – Biz Net Technologies** |
| **ISP / Provedor** | **Biz Net Technologies** (BNT‑NETWORK‑ACCESS) |
| **Cidade / Região / País** | **Blacksburg, Virginia, Estados Unidos** |
| **Latitude / Longitude** | **37.2296 / ‑80.4139** |
| **Faixa de IP** | **216.252.192.0 – 216.252.207.255** (/20) |
| **Tipo de rede** | Data‑center / Fixed‑Line ISP (não é proxy, VPN ou TOR) |
| **Contato de rede** | e‑mail: **biznet@bnt.com** – telefone: **+1‑540‑961‑7560** |

---

## 5. Recomendações (próximos passos)

1. **Correlacionar logs internos** – Verificar tráfego de saída/inbound nos firewalls, IDS/IPS e proxies para conexões com **216.252.199.59**, especialmente nas portas 443, 8443 ou outras não‑padrão.  
2. **Monitoramento contínuo** – Adicionar o IP a *watchlist* no Shodan, VirusTotal Monitor e nas correlações do SIEM para alertas de novas descobertas.  
3. **Análise de tráfego TLS** – Dado que os *pulses* OTX mencionam “cipher‑suite” e “TLS handshake”, capturar e inspecionar pacotes TLS pode revelar padrões de C2 ou uso de certificados falsos.  
4. **Varredura controlada** – Realizar scan de portas (ex.: `nmap -sS -p- -T4 216.252.199.59`) a partir de um ponto externo autorizado para confirmar a inexistência de serviços ocultos.  
5. **Consultas a feeds de botnet** – Verificar presença do IP em listas de **Qakbot**, **Mirai**, **Gafgyt** via AbuseCH, MalwareBazaar ou OTX.  
6. **Passive DNS / Históricos** – Investigar domínios associados ao IP em bases de passive DNS (ex.: `*.clickandpledge.com`) para identificar possíveis pivôs de phishing.  
7. **Contato com ISP** – Caso se confirme atividade suspeita, notificar **Biz Net Technologies** (biznet@bnt.com) para investigação de abuso na rede.  
8. **Revisar certificados** – Se houver tráfego HTTPS identificado, analisar os certificados apresentados; certificados expirados ou auto‑assinados podem indicar uso em ataque *Man‑in‑the‑Middle*.  

---

## 6. Considerações Finais
Embora o IP **216.252.199.59** não exponha serviços públicos e não apareça em listas de bloqueio amplas, ele está **presente em múltiplas fontes de ameaça avançada** que o vinculam a **botnets**, **phishing financeiro** e possíveis **infraestruturas de comando e controle**. Essa combinação de “perfil baixo” (sem portas) com **associação a campanhas de alto impacto** eleva o risco de que o endereço seja usado como ponto de apoio ou relay em ataques direcionados.  

A principal linha de defesa deve ser **monitoramento ativo e correlação de logs internos**, além de **investigações adicionais de tráfego TLS** e **consulta a feeds de botnet**. Caso sejam detectados sinais de comunicação suspeita, uma resposta coordenada com o ISP e a equipe de resposta a incidentes (CSIRT) será essencial para conter possíveis abusos.