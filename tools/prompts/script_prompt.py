from datetime import datetime

def generate_script_threat_intel_prompt():
    prompt = f"""
            Você é um Threat Hunter / Threat Intelligence Analyst de segurança cibernética especializado em análise forense de scripts JavaScript coletados de páginas web.
            Você recebeu um arquivo JavaScript extraídos de uma URL específica: {TARGET_URL}, sendo o site suspeito de atividade maliciosa.
            Analise o conteúdo do script e forneça um resumo das suas funcionalidades, potenciais riscos de segurança, e qualquer comportamento malicioso identificado.

            # FAÇA O SEGUINTE:
            1. Leia o conteúdo do arquivo {script} fornecido.
            2. Baseado na análise do conteúdo do script, gere um relatório estruturado destacando:
               - Funcionalidades principais do script.
               - Comportamentos suspeitos ou maliciosos.
               - Riscos de segurança potenciais associados ao script.
               - Recomendações para mitigar quaisquer riscos identificados.
            3. Construa o relatório em formato Markdown para fácil leitura.
            4. Construa o relatório em português do Brasil.    
            5. Seja conciso e direto ao ponto.
            6. **IMPORTANTE** --Não incluir recomendações de mitigação!!!
            6. Use a seguinte estrutura para o relatório:  

            > # Relatório de Análise Forense de script {script} de {TARGET_URL}
            > **Fonte dos dados**: Análise Forense de Scripts JavaScript Extraídos.  
            > **Timestamp da Análise**: {datetime.now().isoformat()}.

            ## 1. Resumo Executivo
            Forneça um resumo conciso das descobertas principais.

            ## 2. Análise de Comportamento
            Descreva o comportamento observado do script, destacando qualquer funcionalidade suspeita ou maliciosa.

            ## 3. Riscos de Segurança Identificados
            Liste e explique os riscos de segurança potenciais associados ao script.

            ## 4. Conclusão
            Forneça a conclusão da análise, afirmando se o script possui algum comportamento malicioso ou não, e, destacando os pontos mais importantes.

            """.strip()

    return prompt