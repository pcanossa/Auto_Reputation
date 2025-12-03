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

def calculate_sha_ip_domain_files(report_path, data_path):
    report_hash = calculate_sha256(report_path)
    data_hash = calculate_sha256(data_path)
    print(f"\n[+] SHA256 do relatório: {report_hash}")
    print(f"[+] SHA256 dos dados coletados: {data_hash}")

def main():
   print("\n=================SISTEMA DE ANÁLISE DE REPUTAÇÃO AUTOMÁTICA=================\n")
   print("TIPOS DE ANÁLISES DISPONÍVEIS")
   print("[1]. Análise de Domínio")
   print("[2]. Análise de IP")
   print("[3]. Análise de Scripts\n")
   print("===========================================================================\n")
   choice = input("Digite o número da opção desejada: ")
   if choice == "1":
       report_path, data_path = run_domain_analysis()
       if report_path and data_path:
           calculate_sha_ip_domain_files(report_path, data_path)        
   elif choice == "2":
       report_path, data_path = run_ip_analysis()
       if report_path and data_path:
           calculate_sha_ip_domain_files(report_path, data_path)            
   elif choice == "3":
      report_path = run_scripts_analysis()
      if report_path:
          for report in report_path:
              report_full_path = f'./reports/{report}'
              report_hash = calculate_sha256(report_full_path)
              print(f"[+] SHA256 do relatório {report}: {report_hash}")
   else:
       print("Opção inválida. Encerrando o programa.")
       sys.exit(1)

if __name__ == "__main__":
   main()