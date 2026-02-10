# Relatório de Threat Intelligence – IP 216.252.199.59

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN RDAP (via VirusTotal), URLScan.io, VirusTotal, AbuseIPDB, AlienVault OTX, Scamalytics, VPNAPI.
> **Timestamp da Análise**: 2026-02-10T11:36:37.935453.

## 1. Resumo Executivo
O IP 216.252.199.59 está localizado em Blacksburg, Virginia, EUA, e pertence ao provedor **Biz Net Technologies (AS31827)**. Embora ferramentas de scan de superfície (Shodan) não tenham detectado portas abertas e a reputação geral seja majoritariamente limpa (AbuseIPDB: 0, Scamalytics: baixo risco), o IP apresenta **indicadores concretos de atividade maliciosa**. Foi detectado como malicioso por um motor no VirusTotal (SOCRadar) e, mais significativamente, está listado em múltiplos **Pulses do AlienVault OTX** associados a campanhas de **phishing financeiro (fraude ao IRS)**, distribuição de malware (ex: Qakbot) e possíveis ataques de **homem-no-meio (MitM)**. A ausência de portas abertas pode indicar um sistema infectado atuando como cliente/bot ou um host que responde apenas a comandos específicos de C2.

## 2. Análise de Comportamento
Existem fortes evidências de que este IP está ou esteve envolvido em operações maliciosas:

*   **Associação a Campanhas de Phishing/Financiero**: O AlienVault OTX lista este IP em vários "Pulses" (ex: ID `694dc80ac6e7fd5474b316a1`) que descrevem campanhas complexas de **phishing que visam o portal de pagamentos do IRS dos EUA**. Os ataques redirecionam vítimas para domínios falsos (ex: `sa.www4.irs.gov`) para roubo de credenciais e dados financeiros.
*   **Associação a Malware**: Os mesmos Pulses vinculam o IP a famílias de malware como **Qakbot (Qbot)**, **Mirai**, **Gafgyt** e outros. Qakbot é um malware bancário e botnet conhecido por roubar credenciais e facilitar ataques subsequentes.
*   **Indicador em Feeds de Ameaças (VirusTotal)**: Um dos 93 motores de análise (SOCRadar) classificou o IP como "malicioso". Embora seja uma única detecção, combinada com os dados do OTX, aumenta a confiança na natureza maliciosa do endereço.
*   **Comportamento de Rede**: A tentativa de conexão HTTP (cURL) resultou em timeout, sugerindo que o host não hospeda um serviço web público padrão ou está ativamente filtrando conexões. Este comportamento pode ser consistente com um **nó de comando e controle (C2)** que só responde a bots específicos ou um host infectado em modo de escuta.
*   **Ausência de Relatórios de Abuso Direto**: O AbuseIPDB não possui relatórios recentes e dá uma pontuação de confiança de 0. Isso pode indicar que a atividade maliciosa é recente, sofisticada (não detectada por usuários finais) ou que o IP é usado em estágios iniciais de ataques (como scan ou distribuição) sem gerar queixas diretas.

## 3. Superfície de Ataque

### Portas Abertas e Serviços
*   **Nenhuma porta aberta** foi identificada pelo Shodan na data da consulta. O teste de conexão HTTP na porta 80 também falhou (timeout). **Não foi possível identificar serviços ativos publicamente expostos.**

### Vulnerabilidades (CVEs)
*   **Nenhuma vulnerabilidade (CVE)** foi listada pelo Shodan para este IP.
*   **Contexto de Ameaça:** A ausência de CVEs conhecidos não reduz o risco. O IP é um vetor de ameaça baseado em **engenharia social (phishing)** e potencial **distribuição de malware**. O risco principal reside em seu uso como origem de tráfego de ataque, ponto de redirecionamento malicioso ou parte de uma infraestrutura de botnet.

## 4. Informações de Rede e Geográficas

*   **ASN:** AS31827 - Biz Net Technologies (BNT-4).
*   **Provedor (ISP):** Biz Net Technologies.
*   **Localização:** Blacksburg, Virginia, United States (US).
*   **Coordenadas:** Latitude ~37.2532, Longitude ~-80.4347.
*   **Faixa de IP:** 216.252.192.0/20 (pertencente à Biz Net Technologies).

## 5. Recomendações

1.  **Bloqueio em Perímetro:** Recomenda-se **bloquear tráfego** de e para o IP `216.252.199.59` em firewalls, sistemas de prevenção de intrusão (IPS) e gateways web, devido às suas associações ativas com campanhas de phishing e malware.
2.  **Busca Retroativa em Logs:** Pesquisar em logs de firewall, proxy web e DNS por conexões originadas deste IP nos últimos 90 a 180 dias. Procurar por padrões de acesso a domínios relacionados ao IRS ou a outros alvos de phishing mencionados nos Pulses do OTX.
3.  **Monitoramento de Feeds:** Incluir este IP na lista de monitoramento de feeds de inteligência de ameaças para detectar novas associações ou alterações em seu comportamento.
4.  **Análise de Artefatos Associados:** Investigar os hashes de arquivo e domínios listados nos Pulses do AlienVault OTX que mencionam este IP (ex: `sa.www4.irs.gov`), para identificar outros indicadores de comprometimento (IOCs) relacionados.
5.  **Verificação de Comunicações Internas:** Em ambientes corporativos, verificar se algum sistema interno estabeleceu conexões com este IP, o que poderia indicar um comprometimento interno (infecção por malware, acesso a phishing).

---
*Relatório gerado para fins de inteligência defensiva. As recomendações visam proteger redes e usuários de potenciais ameaças originadas ou associadas ao IP analisado.*