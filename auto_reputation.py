from tools.domain_analysis import run_domain_analysis
from tools.ip_analysis import run_ip_analysis
import sys

def main():
   print("\n=================SISTEMA DE ANÁLISE DE REPUTAÇÃO AUTOMÁTICA=================\n")
   print("Escolha o tipo de análise que deseja realizar:")
   print("[1]. Análise de Domínio")
   print("[2]. Análise de IP\n")
   choice = input("Digite o número da opção desejada: ")
   if choice == "1":
       run_domain_analysis()
   elif choice == "2":
       run_ip_analysis()
   else:
       print("Opção inválida. Encerrando o programa.")
       sys.exit(1)

if __name__ == "__main__":
    main()