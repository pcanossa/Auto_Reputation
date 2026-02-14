from tools.domain_analysis import run_domain_analysis
from tools.ip_analysis import run_ip_analysis
from tools.scripts_analysis import run_scripts_analysis
from tools.filehash_analysis import run_filehash_analysis
import sys
import hashlib

VERDE = '\033[92m'
RESET = '\033[0m'
NEGRITO = '\033[1m'
LIGHT_BLUE = "\033[1;36m"
AMARELO = '\033[93m'

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def calculate_files_sha256(file_paths, type_analysis):
    sha256_hashes = []
    for path in file_paths:
        hash_value = calculate_sha256(path)
        sha256_hashes.append(f'{path} = {hash_value}')
        if type_analysis == "domain" or type_analysis == "ip" or type_analysis == "filehash":
            print(f"[{LIGHT_BLUE}{NEGRITO}+{RESET}] SHA256 do arquivo {path}: {hash_value}")
    create_sha_file(sha256_hashes, type_analysis)


def calculate_sha_ip_domain_files(report_path, data_path):
    report_hash = calculate_sha256(report_path)
    data_hash = calculate_sha256(data_path)
    print(f"\n[{LIGHT_BLUE}{NEGRITO}+ {RESET}] SHA256 do relatório: {report_hash}")
    print(f"[{LIGHT_BLUE}{NEGRITO}+ {RESET}] SHA256 dos dados coletados: {data_hash}")

def create_sha_file(sha256_array, type_analysis):
    file_name = f"{type_analysis}_analysis_sha256_hashes.txt"
    with open(f"./reports/{file_name}", "w") as sha_file:
        for item in sha256_array:
            sha_file.write(f"{item}\n")
    print(f"\n[{LIGHT_BLUE}{NEGRITO}+{RESET}] Hashes de integridade salvas com sucesso em: /reports/{file_name}")



def main():
   print(f"\n{LIGHT_BLUE}{NEGRITO}{'='*10}SISTEMA DE ANÁLISE DE REPUTAÇÃO AUTOMÁTICA{'='*10}{RESET}\n")
   print(f"{LIGHT_BLUE}{NEGRITO}TIPOS DE ANÁLISES DISPONÍVEIS{RESET}\n")
   print(f"{VERDE}{NEGRITO}[1]{RESET}. Análise de Domínio")
   print(f"{VERDE}{NEGRITO}[2]{RESET}. Análise de IP")
   print(f"{VERDE}{NEGRITO}[3]{RESET}. Análise de Scripts")
   print(f"{VERDE}{NEGRITO}[4]{RESET}. Análise de Hash de Arquivo\n")
   print(f"{LIGHT_BLUE}{NEGRITO}{'='*62}{RESET}\n")
   choice = input("Digite o número da opção desejada: ")
   files=[] 

   if choice == "1":
       files, sanitized_domain= run_domain_analysis()
       choice=sanitized_domain       
   elif choice == "2":
       files, sanitized_ip = run_ip_analysis()
       choice=sanitized_ip        
   elif choice == "3":
       files = run_scripts_analysis()
       choice="scripts"
   elif choice == "4":
       files = run_filehash_analysis()
       choice="filehash"
   else:   
       print("Opção inválida. Encerrando o programa.")
       sys.exit(1)

   if len(files) > 0:
       calculate_files_sha256(files, choice)

if __name__ == "__main__":
   main()