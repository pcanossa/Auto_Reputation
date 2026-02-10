# Relatório de Threat Intelligence – IP **216.252.199.59**

> **Fonte dos dados**: Shodan, IPInfo.io, VirusTotal, AbuseIPDB, AlienVault OTX, Scamalytics, VPNAPI, RDAP/ARIN.  
> **Timestamp da Análise**: 2026‑02‑10T11:41:10.019702.

---

## 1. Resumo Executivo
O endereço **216.252.199.59** pertence ao bloco /21 alocado à **Biz Net Technologies (AS31827)**, localizado em **Blacksburg, Virginia, EUA**. Os feeds de inteligência (VirusTotal, OTX) apontam para *um único* resultado **malicious** (SOCRadar) e várias *pulses* que associam o IP a campanhas de **Qakbot**, **Mirai** e ataques DDoS direcionados a portais da **IRS**. Não há serviços HTTP/TCP/UDP expostos nas varreduras públicas do Shodan (404 Not Found) e o endereço não aparece em listas de bloqueio (AbuseIPDB score 0, Scamalytics low risk). O perfil indica um host hospedado em data‑center de um ISP de pequeno porte, sem indícios de ser proxy, VPN ou TOR.

---

## 2. Análise de Comportamento

| Fonte | Evidência | Interpretação |
|------|-----------|---------------|
| **VirusTotal** | 60 harmless, 1 malicious (SOCRadar), 32 undetected | Predominantemente “clean”, porém a presença de **1 deteção maliciosa** sugere algum incidente pontual ou artefato associado. |
| **AlienVault OTX** | Pulses que relacionam o IP a **Qakbot / Botnet**, **Mirai**, **DDoS** contra sites da *IRS*; tags de *cipher‑suite*, *TLS handshake* e *Man‑in‑the‑Middle* | Indica que o endereço pode ter sido usado como **infraestrutura de comando e controle (C2)** ou como *relé* em campanhas de fraude financeira. |
| **Shodan** | Página 404 – “No information available”. Nenhuma porta revelada. | O host provavelmente não oferece serviços públicos (HTTP/HTTPS) ou está protegido por firewall que impede a sondagem. |
| **AbuseIPDB / Scamalytics / VPNAPI** | Score 0, risco baixo, não é proxy/VPN/TOR, não está em blacklist. | Não há sinal de abuso massivo reconhecido por essas fontes, mas a ausência de informação pode ser deliberada (host “stealth”). |
| **RDAP / WHOIS** | Registrado para **Biz Net Technologies**, endereço de contato em Blacksburg (2200 Kraft Dr., Suite 2250). | Indica propriedade legítima de um provedor de serviços de internet, possivelmente usado por clientes ou por “cloud hosting”. |

**Conclusão:** Embora o IP não exponha serviços públicos, ele está **presente em indicadores de ameaças avançadas (IA)** ligados a *botnets* e *fraudes contra órgãos governamentais*. O risco está concentrado em **possível uso como ponto de apoio (C2, relay, staging)** em ataques direcionados.

---

## 3. Superfície de Ataque

### 3.1 Portas abertas / Serviços
- **Nenhum dado de portas** foi retornado pelo Shodan (404).  
- Tentativa de conexão na porta **80/TCP** com *curl* resultou em *timeout* → serviço indisponível ou filtrado.

> **Observação:** A ausência de portas visíveis pode ser fruto de firewall de bloqueio de varredura ou de serviços que só operam em portas não‑padrão ou dentro de VPNs internas.

### 3.2 Vulnerabilidades (CVEs) detectadas
- **Nenhuma CVE** foi listada nas respostas do Shodan ou de outras fontes.  
- Como não há serviços identificados, não há vulnerabilidades de software conhecidas a relatar neste momento.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|------|-------|
| **ASN** | **AS31827 – Biz Net Technologies** (BNT‑NETWORK‑ACCESS) |
| **ISP / Provedor** | **Biz Net Technologies** (BNT‑4) |
| **Cidade / Região / País** | **Blacksburg, Virginia, Estados Unidos (US)** |
| **Latitude / Longitude** | **37.2296 / ‑80.4139** (IPInfo) – **37.2532 / ‑80.4347** (MaxMind) |
| **Faixa de IP** | **216.252.192.0 – 216.252.207.255** (/20) |
| **Tipo de rede** | Data‑center / Fixed‑Line ISP (não é proxy, VPN ou TOR) |
| **Organização de contato** | Biz Net Technologies – e‑mail **biznet@bnt.com**, telefone **+1‑540‑961‑7560** |

---

## 5. Recomendações (próximos passos)

1. **Correlacionar logs internos** – Verificar firewalls, IDS/IPS e logs de proxy para tráfego de/para **216.252.199.59** (especialmente portas 443, 8443 ou outras não‑padrão).  
2. **Monitoramento contínuo** – Adicionar o IP a um *watchlist* no Shodan, VirusTotal Monitor e em soluções SIEM para deteções de conexões suspeitas.  
3. **Análise de tráfego TLS** – Dado que pulses OTX mencionam “cipher‑suite” e “TLS handshake”, capturar e analisar pacotes TLS para identificar possíveis *malformed* handshakes ou *SSL‑stripping*.  
4. **Verificação de indicadores de C2** – Procurar por domínios ou sub‑domínios relacionados em *passive DNS* (ex.: `co.clickandpledge.com`) que apareceram na amostra de malware Android associada ao IP.  
5. **Consultas adicionais a feeds de botnet** – Checar se o IP aparece em listas de **Qakbot**, **Mirai**, **Gafgyt**, entre outras, usando APIs de AbuseCH, MalwareBazaar ou o próprio OTX.  
6. **Teste de alcance de portas** – Realizar varredura controlada (ex.: nmap –sS –p‑‑) a partir de um ponto externo autorizado para confirmar a inexistência de serviços ocultos.  
7. **Avaliar relação com o certificado SSL** – O certificado encontrado (`co.clickandpledge.com`) expira em 2020 – pode indicar reutilização de certificados antigos em infra‑estrutura comprometedora; atualizar ou revogar, se for um ativo interno.  
8. **Comunicação com o ISP** – Caso ocorram incidentes confirmados, notificar **Biz Net Technologies** (contato biznet@bnt.com) para investigação de eventuais abusos de sua rede.  

---

## 6. Considerações Finais
O IP **216.252.199.59** não apresenta serviços abertos publicamente e não está listado em listas de bloqueio comuns, mas aparece em múltiplas *pulses* de ameaças avançadas que ligam o endereço a **botnets de pagamento fraudulento** e **ataques DDoS contra a Receita Federal dos EUA (IRS)**. Embora a maioria das análises (VT, Scamalytics) classifique o host como “clean”/“low risk”, a presença de um único sinal **malicious** e a associação a campanhas de malware indicam que ele pode ser utilizado como **código de apoio (staging)** ou **relay** em campanhas dirigidas.

A recomendação principal é **monitoramento ativo e correlação com tráfego interno**, bem como a **validação de possíveis conexões TLS anômalas**. Caso alguma comunicação suspeita seja confirmada, uma resposta rápida envolvendo o ISP e a equipe de resposta a incidentes (CSIRT) será essencial para mitigar o risco de comprometimento de infraestrutura interna ou de ser usado como vetor em ataques a terceiros.