from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from urllib.parse import urlparse
from tools.prompts.script_prompt import generate_script_threat_intel_prompt
import json
import hashlib
import time
import os
import subprocess
from ollama import Client
from datetime import datetime

def run_scripts_analysis():
    files=[]

    client = Client()

    TARGET_URL = input("Digite a URL alvo (ex: http://example.com): ").strip()
    if not TARGET_URL.startswith(("http://", "https://")):
        TARGET_URL = "http://" + TARGET_URL
    sanitized_url= TARGET_URL.replace('http://', '').replace('https://', '').replace('/', '_').replace('.', '_')    
    OUTPUT_FILE = f"scanned_scripts_{sanitized_url}"

    def calculate_sha256(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def wget_scripts(js, name):
        print(f"\n[*] Baixando script {name} com wget...")
        try :
            result = subprocess.run(
                ['wget', '-O', f'./reports/{name}', js], 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                print(f"[!] Erro ao baixar {name}: {result.stderr}")
            else:
                print(f"[+] Script {name} baixado com sucesso.")
                print(f"[+] SHA256 do script {name}: {calculate_sha256(f'./reports/{name}')}")
                files.append(f'./reports/{name}')  
                return f'{name}'  

        except Exception as e:
            print(f"[!] Erro ao baixar {js}: {e}")

    def get_clean_filename(url, index):
        if not url:
            return f"inline_script_{index}.js"

        try:
            parsed = urlparse(url)
            path = parsed.path
            filename = os.path.basename(path)

            if not filename or filename == "/":
                return "index.js" 

            return filename
        except:
            return f"unknown_script_{index}.js"

    print(f"\n[*] Iniciando coleta de scripts em: {TARGET_URL}")

    chrome_options = Options()
    chrome_options.add_argument("--headless") 
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")

    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(TARGET_URL)

        print("[*] Aguardando renderização completa (5s)...")
        time.sleep(5)

        script_elements = driver.find_elements(By.TAG_NAME, "script")
        print(f"[*] Encontrados {len(script_elements)} scripts.")

        extracted_data = []
        files_created = []

        for idx, script in enumerate(script_elements):
            src = script.get_attribute("src")
            content = script.get_attribute("innerHTML")

            # Lógica de Nomenclatura e Tipo
            script_type = "External" if src else "Inline"
            filename = get_clean_filename(src, idx + 1)
            full_url = src if src else "N/A (Embedded inside HTML)"

            # Hash do conteúdo (se for inline) ou da URL (se for externo) para integridade
            content_hash = "N/A"
            if content:
                content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            elif src:
                # Para externos, hash da string da URL como identificador único rápido
                content_hash = hashlib.sha256(src.encode('utf-8')).hexdigest()

            script_info = {
                "id": idx + 1,
                "filename": filename,    
                "type": script_type,
                "full_url": full_url,   
                "content_snippet": content[:150] + "..." if content else "N/A (External File)",
                "integrity_hash": content_hash
            }
            extracted_data.append(script_info)

            new_file = wget_scripts(full_url, filename) if src else None
            if new_file:
                files_created.append(new_file)

        # Relatório Final
        report = {
            "target": TARGET_URL,
            "scan_date": datetime.now().isoformat(),
            "total_scripts_found": len(script_elements),
            "scripts": extracted_data
        }

        with open(f'./reports/{OUTPUT_FILE}.json', "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        print(f"\n[+] Relatório salvo em: {OUTPUT_FILE}.json")

        # Hash do arquivo final
        file_hash = calculate_sha256(f'./reports/{OUTPUT_FILE}.json')
        print(f"[+] SHA256 do Arquivo {OUTPUT_FILE}.json: {file_hash}")
        files.append(f'./reports/{OUTPUT_FILE}.json')


    except Exception as e:
        print(f"[!] Erro: {e}")

    # Análise com LLM
    if len(files_created) > 0:
        reports = []
        for script in files_created:
            with open(f'./reports/{script}', "r", encoding="utf-8", errors="ignore") as f:
                script_content = f.read().splitlines()
            script_content = "\n".join(script_content)



            prompt = generate_script_threat_intel_prompt()

            print(f"\n[*] Iniciando análise LLM para o script: {script}")
            message = [
                {
                    "role": "system", "content": "Você é um assistente especializado em análise forense de scripts JavaScript."},
                {
                    "role": "user", 
                    "content": prompt
                },
                {
                    "role": "user",
                    "content": f"SCRIPT: {script_content}"
                }
            ]

            print(f"\n=========>> Analisando e gerando relatório...\n")
            full_response = []
            try:
                for part in client.chat(
                    model='gpt-oss:120b-cloud',
                    messages=message,
                    stream=True
                ):
                    content = part['message']['content']
                    full_response.append(content)

            except Exception as e:

                print(f"[!] Erro ao comunicar com o modelo de IA: {e}")
            
            print(f"\n\n--- Fim da Análise do Script {script}---")

            report_filename = f"script_analisys_{script.replace('.js', '')}.md"

            with open(f'./reports/{report_filename}', "w", encoding="utf-8") as report_file:
                report_file.write("".join(full_response))
            print(f"[+] Relatório salvo com sucesso em: /reports/{report_filename}")
            file_hash = calculate_sha256(f'./reports/{report_filename}')
            print(f"[+] SHA256 do Arquivo {report_filename}: {file_hash}")
            files.append(f'./reports/{report_filename}')

    else:
        print("[!] Nenhum script externo baixado para análise LLM.")
    
    print ("\n")

    return files
