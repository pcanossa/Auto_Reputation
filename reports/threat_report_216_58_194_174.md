# Relatório de Threat Intelligence – IP **216.58.194.174**

> **Fonte dos dados**: Shodan, IPInfo.io, URLScan.io, VirusTotal (sem resultados), AbuseIPDB, WHOIS (MarkMonitor), AlienVault OTX, Scamalytics, diversos feeds de reputação (FireHOL, Spamhaus, etc.).  
> **Timestamp da Análise**: 2026-01-09T14:44:32.451578  

---

## 1. Resumo Executivo
O endereço **216.58.194.174** pertence ao bloco de IPs da **Google LLC** (ASN 15169) e está associado ao hostname `sfo07s13-in-f14.1e100.net`, localizado em **San Francisco, Califórnia, EUA**. Não foram encontradas portas abertas ou serviços responsivos nas verificações realizadas (cURL falhou ao conectar na porta 80) e o Shodan retornou “404: Not Found”, indicando ausência de banners ou serviços expostos. Os feeds de reputação (AbuseIPDB, Scamalytics, FireHOL, Spamhaus) apontam **risco baixo**, sem relatos de abuso ou listagens em listas negras. Embora o IP apareça em alguns pulsos do AlienVault OTX, esses parecem referir‑se genericamente a domínios de propriedade da Google e não a comportamentos maliciosos específicos deste endereço. Em suma, o IP comporta‑se como um **ativo legítimo de infraestrutura da Google**, sem indícios claros de ser usado como botnet, scanner ou servidor C2.

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **Shodan** | Página 404 (nenhum serviço descoberto) | Não há serviços públicos expostos. |
| **cURL (porta 80)** | Timeout → conexão falhou | Não há serviço HTTP ativo visível ao público. |
| **AbuseIPDB** | Abuse Confidence Score = 0, 0 relatórios | Nenhuma denúncia de atividade maliciosa. |
| **Scamalytics / FireHOL / Spamhaus** | Risco “low”, não listado em blacklists | IP classificado como de data‑center confiável (Google). |
| **AlienVault OTX** | Pulsos que citam “google.com”, “as15169”, mas sem indicadores diretos ao IP | Referências genéricas ao domínio/ASN da Google; não constituem evidência de comprometimento. |
| **WHOIS** | Registrado a Google LLC via MarkMonitor; domínio `1e100.net` (domínio interno da Google) | Confirma propriedade legítima. |
| **URLScan.io** | Várias capturas de visitas ao domínio `www.google.com` usando IPv6, sem anomalias | IP usado como ponto de saída de tráfego legítimo da Google. |

**Conclusão:** Não há indícios de que o IP esteja envolvido em atividades de botnet, scanners ou servidores de comando e controle. O comportamento observado coincide com o de um servidor de fronteira ou balanceador de carga da Google.

---

## 3. Superfície de Ataque
### Portas e Serviços Detectados
- **Nenhuma porta aberta detectada** nas sondagens realizadas (Shodan, cURL).
- **Serviços conhecidos** (por associação de IP a blocos da Google) incluem HTTP / HTTPS (porta 80/443) em servidores de borda, mas **não foram identificados banners** ou serviços responsivos neste IP específico.

### Vulnerabilidades (CVEs) Identificadas
- **Nenhuma vulnerabilidade CVE listada** nos resultados do Shodan ou nas bases consultadas para este endereço.
- Como não há serviços expostos, a superfície de ataque que poderia ser explorada por vulnerabilidades conhecidas é **praticamente inexistente**.

---

## 4. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS15169 – Google LLC** |
| **ISP / Provedor** | **Google LLC** |
| **Organização** | Google LLC |
| **Hostname** | `sfo07s13-in-f14.1e100.net` |
| **Localização** | **San Francisco**, Califórnia, Estados Unidos (lat 37.7749, lon ‑122.4194) |
| **Cidade** | San Francisco |
| **Região / Estado** | Califórnia |
| **País** | US (Estados Unidos) |
| **Tipo de uso** | Data Center / Web Hosting / Transit (conforme AbuseIPDB) |

---

## 5. Recomendações de Investigação
1. **Monitoramento de Tráfego**  
   - Verificar logs de firewall/IDS para quaisquer conexões iniciadas *a partir* deste IP (saídas), especialmente se houver suspeita de *exfiltração* ou comunicação com hosts internos.  
2. **Correlações com Feeds de Ameaças**  
   - Incluir o IP em consultas regulares a feeds como OTX, MISP, URLHaus, e outras bases de indicadores de comprometimento (IoCs).  
3. **Validação de Serviços**  
   - Realizar scans de portas específicas (443, 80, 22, 53) em horários de baixa demanda para confirmar a ausência de serviços inesperados.  
4. **Análise de DNS**  
   - Consultar registros DNS (A, PTR, CNAME) para detectar possíveis mudanças de apontamento que possam sinalizar uso malicioso do IP (ex.: apontamento a domínios de phishing).  
5. **Auditoria de Logs de Aplicações**  
   - Caso haja serviços internos que façam chamadas a APIs externas, registrar se este IP aparece como endpoint legítimo ou inesperado.  
6. **Revisão de Configurações de Segurança da Rede**  
   - Garantir que políticas de *allow‑list* para IPs da Google estejam corretas, evitando bloqueios indevidos que poderiam gerar falsos‑positivos.

---

## 6. Considerações Finais
- O IP **216.58.194.174** se apresenta como parte da robusta e amplamente confiável infraestrutura de rede da Google.  
- Não há evidências de comportamento malicioso ativo ou histórico de abuso.  
- A baixa pontuação de risco e a ausência de portas abertas reduzem significativamente a probabilidade de uso como vetor de ataque.  
- **Recomendação principal:** manter monitoramento rotineiro e inclusão em listas de observação, mas não há necessidade de ações corretivas imediatas.  

--- 

*Este relatório tem como objetivo apoiar equipes de defesa e analistas de threat intelligence na avaliação do risco associado ao endereço IP em questão. Qualquer decisão de bloqueio ou mitigação deve considerar o contexto da sua organização e a necessidade de manter a conectividade com serviços legítimos da Google.*