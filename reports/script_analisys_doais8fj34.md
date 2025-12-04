# Relatório de Análise Forense de script doais8fj34.js de http://teste.com  
**Fonte dos dados**: Análise Forense de Scripts JavaScript Extraídos.  
**Timestamp da Análise**: 2025-12-04T13:20:50.749304  

## 1. Resumo Executivo
O script `doais8fj34.js` implementa uma camada de entrega de anúncios baseada em Google Ads for Domains (AFD). Ele realiza:

- Coleta de informações de contexto (referrer, user‑agent, dimensões da viewport, etc.) e envio ao endpoint `/_d`.
- Tratamento de respostas que podem redirecionar usuários, servir anúncios via AFD, ou encaminhar a URLs de fallback.
- Registro detalhado de eventos (viewport, carregamento de blocos, erros) para o endpoint `/_e`.
- Exibição de mensagens de erro/contato e injeção de estilos/customizações definidas pelo servidor.
- Detecção de bloqueadores de anúncios e redirecionamento para páginas específicas (`/_a`, `/_c`, `/_o`).

## 2. Análise de Comportamento
| Componente | Função observada | Comentário |
|------------|------------------|------------|
| **Debounce** | Função utilitária para limitar a frequência de eventos de mouse/scroll. | Usada para garantir que o registro de viewport ocorra apenas uma vez. |
| **CONFIG** | Definições de endpoints, script externo (`caf.js`), mensagens de erro. | Centraliza URLs e strings usadas ao longo do código. |
| **DeliveryError** | Classe de erro customizada carregando código e detalhes. | Facilita tratamento de falhas específicas da entrega. |
| **UIManager** | Manipula DOM: exibição de container, mensagens de erro, título da página, banner de contato. | Permite personalização visual baseada nos dados recebidos. |
| **APIClient.fetchPageData** | Envia POST para `/_d` com dados de navegação; trata respostas HTTP não‑OK e erros de servidor; verifica geo‑localização (ex.: redireciona usuários da Rússia). | Função crítica para obter instruções de entrega. |
| **DeliveryApp** | Orquestração principal: valida ambiente, coleta dados, registra viewport, carrega script AFD, inicializa blocos de anúncios, trata redirecionamentos e falhas. | Contém a lógica de decisão de fluxo (redirect → AFD → fallback). |
| **Viewport Logging** | Registra dados de viewport somente após detectar interação humana (mousemove, click, scroll, etc.). | Busca diferenciar usuários reais de bots. |
| **loadAFDScript** | Carrega dinamicamente `https://www.google.com/adsense/domains/caf.js`. Em caso de falha, dispara erro `AD_BLOCK_DETECTED`. | Dependência externa para exibir anúncios. |
| **reportEvent** | Envia eventos genéricos ao endpoint `/_e`. | Estratégia de telemetria para análise posterior. |
| **handlePageLoadedCallback / handleBlockLoadedCallback** | Callbacks de sucesso/erro para carregamento de página e blocos AFD; redireciona para `/ _a`, `/ _o` ou `/ _c` conforme situação (adult, faillist, nofill, etc.). | Controle fino de fluxos de erro. |
| **applyAFDStyles** | Injeta CSS customizado a partir de cores retornadas pela API. | Personaliza aparência dos anúncios. |
| **initializeAFD** | Configura parâmetros do AFD (client_id, drid, style_id, termos relacionados) e cria containers DOM (ads, rs, search). | Integração direta com a biblioteca Google Ads. |
| **Fluxo de inicialização** | - Detecta se está em iframe → redireciona fora. <br> - Verifica parâmetros `afd=1`/`query`. <br> - Busca dados via `fetchPageData`. <br> - Aplica customizações UI. <br> - Executa lógica de entrega (redirect, afd, fallback). | Garante que a página siga o caminho determinado pelo backend. |

## 3. Riscos de Segurança Identificados
1. **Coleta e exfiltração de informações do usuário**  
   - Dados como `referrer`, `userAgent`, dimensões da tela, e `window.location` são enviados ao endpoint `/_d`. Estes podem ser utilizados para fingerprinting avançado e rastreamento cross‑site.

2. **Redirecionamento não‑validado**  
   - O script aceita URLs de redirecionamento vindas da resposta da API (`data.delivery.destination`). Sem validação de lista branca, há risco de **open redirect** para domínios maliciosos.

3. **Injeção de CSS/JS dinâmicos**  
   - Campos `custom_css`, `custom_js` retornados pela API são inseridos diretamente no `<style>` e `<script>` sem sanitização, potencializando **Cross‑Site Scripting (XSS)** caso o servidor seja comprometido.

4. **Dependência de script externo (caf.js)**  
   - Carrega `https://www.google.com/adsense/domains/caf.js`. Se esse arquivo for substituído por um atacante (por ex., em um ataque de comprometimento de CDN), permitirá **execução arbitrária de código** no cliente.

5. **Detecção de bloqueador de anúncios como erro**  
   - Quando o script de ads não carrega, gera erro `AD_BLOCK_DETECTED` e pode redirecionar para páginas de “contato” ou “fallback”, o que pode ser usado para **engano (phishing)** se esses endpoints forem manipulados.

6. **Manipulação de parâmetros de URL**  
   - Parâmetros como `rc` (contador de redirecionamento) são incrementados e reutilizados, permitindo que um atacante “esgote” o contador ou force múltiplos redirecionamentos, levando a **Denial‑of‑Service** ao usuário.

7. **Exposição de identificadores internos**  
   - Mensagens de erro enviam códigos como `SERVER_ERROR`, `NO_CHANNELS`, etc., que podem revelar detalhes da arquitetura interna da plataforma ao atacante.

## 4. Conclusão
O script `doais8fj34.js` desempenha funções avançadas de entrega de anúncios e personalização de página, incluindo coleta de metadados do usuário, registro de eventos, e lógica de redirecionamento baseada em respostas de backend. Várias funcionalidades são potencialmente maliciosas ou de alto risco, destacando‑se a coleta de informações sensíveis, redirecionamento aberto, injeção de CSS/JS sem sanitização, e dependência de recursos externos.

Em resumo, o script apresenta comportamentos **maliciosos ou altamente suspeitos**, sendo capaz de rastrear usuários, redirecioná‑los para destinos possivelmente não confiáveis e executar código arbitrário proveniente de fontes externas ou de dados controlados pelo servidor. Esses comportamentos justificam um nível elevado de cautela ao lidar com a página `http://teste.com`.