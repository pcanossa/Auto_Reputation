> # Relatório de Análise Forense de script doais8fj34.js de http://teste.com  
> **Fonte dos dados**: Análise Forense de Scripts JavaScript Extraídos.  
> **Timestamp da Análise**: 2025-12-03T18:48:30.358714.  

## 1. Resumo Executivo
O script `doais8fj34.js` implementa uma aplicação de entrega de anúncios e conteúdos relacionados (AFD – *AdSense for Domains*). Ele controla a coleta de métricas do navegador, comunicação com um backend interno via **fetch**, carregamento dinâmico de um script remoto da Google (`caf.js`), tratamento de redirecionamentos, exibição de mensagens de erro/contato e aplicação de estilos/customizações recebidas do servidor. O código contém lógica de **detecção de bloqueador de anúncios**, **bloqueio geográfico** (Rússia) e mecanismos para evitar loops de redirecionamento.  

## 2. Análise de Comportamento
| Área | Comportamento observado |
|------|--------------------------|
| **Utilitários** | Função `debounce` para limitar frequência de eventos de mouse/scroll. |
| **Configurações** | Constantes `CONFIG` definem endpoints (`/_d`, `/_a`, `/_c`, `/_e`, `/_o`) e mensagens de erro. |
| **Gerenciamento de UI** | Classe `UIManager` controla exibição de container, mensagens de erro, título da página e banner de contato. |
| **Cliente API** | `APIClient.fetchPageData()` envia JSON com referrer, URL atual, contagem de redirecionamentos, user‑agent e informações da janela. Interpreta respostas de erro e redireciona usuários da Rússia ou quando há fallback list. |
| **Log de Métricas** | `logViewportInfo` e `setupViewportLogging()` capturam dimensões da viewport, agente do usuário, foco, orientação, e enviam evento `metric:browser:viewport`. O registro ocorre na primeira interação real do usuário (mousemove, scroll, click, etc.). |
| **Carregamento de Script AFD** | `loadAFDScript()` insere dinamicamente o script `https://www.google.com/adsense/domains/caf.js?abp=1&abpgo=true`. Falha desencadeia erro `AD_BLOCK_DETECTED`. |
| **Eventos de Reporting** | `reportEvent()` POSTa eventos para `/_e` com dados de contexto e `domain_settings`. |
| **Fallback & Redirecionamento** | `attemptFallbackDelivery()` tenta redirecionar para URLs de fallback listadas. Redirecionamentos são controlados por parâmetros `rc` (contagem) e `err`. |
| **Callbacks de AFD** | `handlePageLoadedCallback` e `handleBlockLoadedCallback` processam respostas da biblioteca AFD, registram sucesso/erro e, em casos de falha, redirecionam para `/_a` (adult) ou `/_o` (fallback). |
| **Aplicação de Estilos** | `applyAFDStyles` cria/atualiza stylesheet `#afd-theme` com variáveis CSS vindas de `data.afd.colors`. |
| **Inicialização** | `DeliveryApp.initialize()` verifica contexto de iframe, parâmetros `afd`, chamadas à API, exibição de mensagens de erro, aplicação de CSS/JS/text personalizados, configuração de banner de contato, registro de viewport, gerenciamento de redirecionamentos (incluindo loops), e finalmente carrega/instancia a biblioteca AFD. |
| **Execução de Código Remoto** | Se a resposta da API contém `custom_js`, o script o injeta e executa no contexto da página. |
| **Detecção de Bloqueador de Anúncios** | Caso o script AFD não carregue, o erro `AD_BLOCK_DETECTED` é lançado e pode forçar redirecionamentos ou exibir mensagens. |
| **Bloqueio Geográfico** | Usuários com `geo.country === 'RU'` são redirecionados para fallback ou endpoint `/_o`. |
| **Manipulação de Parâmetros de URL** | Parâmetros como `rc`, `afd`, `err`, `query` influenciam fluxo de redirecionamento e exibição de mensagens. |
| **Eventos de Contato** | `configureContactMessage` cria banner ou rodapé com link para `/_c` quando mensagens de contato são fornecidas. |

## 3. Riscos de Segurança Identificados
| Risco | Descrição |
|-------|-----------|
| **Exfiltração de Dados de Navegador** | O script envia referrer, URL completa, user‑agent, e informações de janela ao endpoint `/_d`. Esses dados podem ser usados para fingerprinting ou rastreamento avançado. |
| **Execução de Código Remoto** | Campos `custom_js` e `custom_css` são inseridos diretamente na página sem validação. Um atacante que controle a resposta da API poderia injetar JavaScript malicioso, resultando em **XSS** ou **supply‑chain compromise**. |
| **Redirecionamento Forçado** | Vários caminhos de redirecionamento (`/_a`, `/_o`, URLs de fallback) são definidos dinamicamente com base em parâmetros e respostas da API. Um manipulador malicioso poderia redirecionar usuários para sites de phishing ou malware. |
| **Detecção e Contorno de Ad‑Blockers** | Ao bloquear o script AFD, o código gera mensagens de erro e tenta redirecionar para endpoints alternativos, podendo ser usado para **coerção** de usuários a desabilitar bloqueadores e, assim, expor-os a anúncios potencialmente maliciosos. |
| **Bloqueio Geográfico Discriminatório** | Usuários na Rússia são automaticamente redirecionados, indicando que há lógica de filtragem geográfica que pode ser abusada para **censura** ou **targeting** de grupos específicos. |
| **Loop de Redirecionamento** | O parâmetro `rc` tenta impedir loops, mas se manipulado inadequadamente pode gerar redirecionamentos infinitos, causando **DoS de navegação**. |
| **Coleta de Métricas de Interação** | Eventos de viewport e interações de usuário são enviados para o endpoint `/_e`, possibilitando a criação de perfis comportamentais detalhados sem consentimento explícito. |
| **Manipulação de URL via iframe** | O script detecta execução em iframe e tenta “bust out” adicionando parâmetros `err=frame` e `frame_referrer`. Essa lógica pode ser explorada para **open‑redirect** ou para burlar políticas de mesma origem. |
| **Dependência de recursos externos** | O carregamento do script `https://www.google.com/adsense/domains/caf.js` tem impacto de disponibilidade; se comprometido, pode servir código malicioso. |
| **Possível uso malicioso de parâmetros de consulta** | Parâmetros `afd=1`, `query`, `err` influenciam lógica de exibição e redirecionamento, podendo ser abusados para **URL manipulation attacks**. |

## 4. Conclusão
A análise demonstra que o script `doais8fj34.js` realiza funções típicas de entrega de anúncios e conteúdos relacionados, porém incorpora múltiplas rotinas que podem ser exploradas para fins maliciosos:

* Coleta e transmissão de informações detalhadas do navegador.
* Execução de código JavaScript arbitrário proveniente da resposta da API.
* Redirecionamentos dinâmicos baseados em parâmetros controláveis externamente.
* Detecção de bloqueadores de anúncios que pode forçar o usuário a desabilitá‑los.
* Lógica de bloqueio geográfico e prevenção de loops de redirecionamento.

Embora não seja possível afirmar categoricamente que o script está inserindo malware ativo, seus comportamentos constituem **vetores de risco consideráveis** que podem ser abusados por um ator malicioso para rastreamento, phishing, entrega de anúncios indesejados ou execução de código arbitrário. Recomenda‑se atenção ao monitoramento de chamadas de rede e à análise das respostas da API para identificar eventuais injeções de código.