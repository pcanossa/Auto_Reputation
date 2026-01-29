import requests
import os
import datetime

def fetch_phishing_lists(domain):

    phishing_list_urls = "Ausente em listas de phishing conhecidas.\n\n"
    phishing_army = requests.get("https://phishing.army/download/phishing_army_blocklist_extended.txt")
    phishing_army.raise_for_status()

    if domain in phishing_army.text:
        phishing_list_urls = "Presente na lista de phishing: phishing_army_blocklist_{datetime.datetime.now().strftime('%d-%m-%Y')}.txt\n"


    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.join(script_dir, '..', 'reports', 'phishing_lists')

    os.makedirs(target_dir, exist_ok=True)

    file_path = os.path.join(target_dir, f"phishing_army_blocklist_{datetime.datetime.now().strftime('%d-%m-%Y')}.txt")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(phishing_army.text)
    
    final_file_path = f"../reports/phishing_lists/phishing_army_blocklist_{datetime.datetime.now().strftime('%d-%m-%Y')}.txt"
    print(f"\n[+] Lista atualizada de phishing utilizada para análise salva em: {final_file_path}")
    final_file_path = f"./reports/phishing_lists/phishing_army_blocklist_{datetime.datetime.now().strftime('%d-%m-%Y')}.txt"

    return phishing_list_urls, final_file_path