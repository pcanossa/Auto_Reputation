from tools.domain_analysis import run_domain_analysis
from tools.ip_analysis import run_ip_analysis
from tools.scripts_analysis import run_scripts_analysis
import sys
import hashlib

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
        if type_analysis == "domain" or type_analysis == "ip":
            print(f"[+] SHA256 do arquivo {path}: {hash_value}")
    create_sha_file(sha256_hashes, type_analysis)


def calculate_sha_ip_domain_files(report_path, data_path):
    report_hash = calculate_sha256(report_path)
    data_hash = calculate_sha256(data_path)
    print(f"\n[+] SHA256 do relatório: {report_hash}")
    print(f"[+] SHA256 dos dados coletados: {data_hash}")

def create_sha_file(sha256_array, type_analysis):
    file_name = f"{type_analysis}_analysis_sha256_hashes.txt"
    with open(f"./reports/{file_name}", "w") as sha_file:
        for item in sha256_array:
            sha_file.write(f"{item}\n")
    print(f"\n[+] Hashes de integridade salvas com sucesso em: /reports/{file_name}")



def main():
   print("\n=================SISTEMA DE ANÁLISE DE REPUTAÇÃO AUTOMÁTICA=================\n")
   print("TIPOS DE ANÁLISES DISPONÍVEIS")
   print("[1]. Análise de Domínio")
   print("[2]. Análise de IP")
   print("[3]. Análise de Scripts\n")
   print("===========================================================================\n")
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
   else:   
       print("Opção inválida. Encerrando o programa.")
       sys.exit(1)

   if len(files) > 0:
       calculate_files_sha256(files, choice)

if __name__ == "__main__":
   main()