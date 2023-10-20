# import requests
# from tqdm import tqdm

# # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
# api_key = '6ba88516f54936e6db7e6813dfe36f21928181b9b19def5d6ce66a489dd4ae96'

# headers = {
#     'x-apikey': api_key
# }

# def check_domain(domain):
#     url = f'https://www.virustotal.com/api/v3/domains/{domain}'
#     response = requests.get(url, headers=headers)
#     if response.status_code == 200:
#         return response.json()
#     else:
#         print(f"Error: Unable to fetch information for domain {domain}")
#         return None

# def get_verdict(analysis_stats):
#     if analysis_stats.get('malicious', 0) > 0 or analysis_stats.get('suspicious', 0) > 0:
#         return "Malign"
#     else:
#         return "Benign"

# def read_domains_from_file(filename):
#     with open(filename, "r") as file:
#         lines = file.readlines()
#     domains = [line.split(",")[0].split(": ")[1] for line in lines]
#     return domains

# def main():
#     domains = read_domains_from_file("false_positives/highest_shap.txt")
#     output_file = open("false_positives/FP_check.txt", "w")
    
#     malign_count = 0
#     total_domains = len(domains)
    
#     for domain in tqdm(domains, desc="Processing domains", unit="domain"):
#         result = check_domain(domain)
#         if result:
#             analysis_stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
#             verdict = get_verdict(analysis_stats)
#             if verdict == "Malign":
#                 malign_count += 1
#             output = (f"Domain: {domain}\n"
#                       f"  Verdict: {verdict}\n"
#                       f"  Harmless: {analysis_stats.get('harmless', 0)}\n"
#                       f"  Malicious: {analysis_stats.get('malicious', 0)}\n"
#                       f"  Suspicious: {analysis_stats.get('suspicious', 0)}\n"
#                       f"  Timeout: {analysis_stats.get('timeout', 0)}\n"
#                       f"  Undetected: {analysis_stats.get('undetected', 0)}\n\n")
#             # print(output)
#             output_file.write(output)
    
#     output_file.close()
    
#     benign_count = total_domains - malign_count
#     print(f"Malign domains: {malign_count}/{total_domains} ({(malign_count/total_domains)*100:.2f}%)")
#     print(f"Benign domains: {benign_count}/{total_domains} ({(benign_count/total_domains)*100:.2f}%)")

# if __name__ == "__main__":
#     main()


import vt
from tqdm import tqdm
from prettytable import PrettyTable

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
api_key = '6ba88516f54936e6db7e6813dfe36f21928181b9b19def5d6ce66a489dd4ae96'

client = vt.Client(api_key)

def check_domain(domain):
    try:
        url_id = vt.url_id(domain)
        obj = client.get_object(f"/urls/{url_id}")
        return obj
    except vt.APIError as e:
        print(f"Error: Unable to fetch information for domain {domain}. {e}")
        return None

def get_verdict(analysis_stats):
    if analysis_stats.get('malicious', 0) > 0 or analysis_stats.get('suspicious', 0) > 0:
        return "Malign"
    else:
        return "Benign"

def read_domains_from_file(filename):
    with open(filename, "r") as file:
        lines = file.readlines()
    domains = [line.split(",")[0].split(": ")[1] for line in lines]
    return domains

def main():
    domains = read_domains_from_file("false_positives/highest_shap.txt")
    output_file = open("false_positives/FP_check.txt", "w")
    
    malign_count = 0
    total_domains = len(domains)
    
    table = PrettyTable(["Domain", "Verdict", "Harmless", "Malicious", "Suspicious", "Timeout", "Undetected"])
    
    for domain in tqdm(domains, desc="Processing domains", unit="domain"):
        result = check_domain(domain)
        if result:
            analysis_stats = result.last_analysis_stats
            verdict = get_verdict(analysis_stats)
            if verdict == "Malign":
                malign_count += 1
            table.add_row([domain, verdict, analysis_stats.get('harmless', 0), 
                           analysis_stats.get('malicious', 0), analysis_stats.get('suspicious', 0), 
                           analysis_stats.get('timeout', 0), analysis_stats.get('undetected', 0)])
    
    output_file.write(table.get_string())
    output_file.close()
    client.close()
    
    benign_count = total_domains - malign_count
    print(f"\nMalign domains: {malign_count}/{total_domains} ({(malign_count/total_domains)*100:.2f}%)")
    print(f"Benign domains: {benign_count}/{total_domains} ({(benign_count/total_domains)*100:.2f}%)\n")
    print(table)

if __name__ == "__main__":
    main()


