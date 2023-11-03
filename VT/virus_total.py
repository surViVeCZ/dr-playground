import os
import subprocess
from typing import List, Tuple, Optional

import vt
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
from dotenv import load_dotenv
import requests
from datetime import datetime


class DomainAnalyzer:
    def __init__(self):
        self.api_key = self.load_api_key()
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    @staticmethod
    def load_api_key():
        load_dotenv()  # Load environment variables from .env file
        api_key = os.getenv('VT_API_KEY')  # Get the API key from the environment variable

        if api_key is None:
            raise ValueError("API key is not set. Please set the VT_API_KEY environment variable.")

        return api_key
        
    @staticmethod
    def read_domains_from_file(filename: str) -> List[str]:
        """
        Read domains from a given file.
        """
        with open(filename, "r") as file:
            lines = [line.strip() for line in file if line.strip()]
        #this return is for FP, saved in highest shap txt
        # return [line.split(",")[0].split(": ")[1] for line in lines]
        return lines

    def check_domain(self, domain: str) -> Optional[dict]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: Unable to fetch information for domain {domain}. {response.text}")
            return None

    def get_verdict(self, analysis_stats: dict) -> str:
        """
        Determine the verdict of the analysis.
        """
        if analysis_stats.get('malicious', 0) > 0 or analysis_stats.get('suspicious', 0) > 1:
            return "Malign"
        else:
            return "Benign"

    def process_domains(self, filename: str) -> pd.DataFrame:
        domains = self.read_domains_from_file(filename)
        data = []

        for domain in tqdm(domains, desc="Processing domains", unit="domain"):
            result = self.check_domain(domain)
            if result:
                domain_data = self.extract_domain_data(domain, result)
                if domain_data:  # Check if domain_data is not None
                    data.append(domain_data)

        columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
        df = pd.DataFrame(data, columns=columns)
        df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
        df.dropna(inplace=True)  # Remove rows with any None values

        return df

    def is_domain_live(self, domain: str) -> str:
        """
        Check if a domain is live by calling a bash script.
        """
        try:
            # Running the bash script and capturing the output
            result = subprocess.run(['./livetest.sh', domain], capture_output=True, text=True)
            output = result.stdout.strip()
            if output == '1':
                return "Alive"
            else:
                return "Dead"
        except Exception as e:
            print(f"Error: Unable to check if domain {domain} is live. {e}")
            return "Unknown"
        
    def extract_domain_data(self, domain: str, result: dict) -> Tuple:
        """
        Extract necessary data from the domain result.
        """
        try:
            analysis_stats = result['data']['attributes']['last_analysis_stats']
        except KeyError:
            print(f"Error: Could not extract analysis stats for domain {domain}")
            return None  # 

        verdict = self.get_verdict(analysis_stats)
        detection_ratio = f"{analysis_stats['malicious']}/{analysis_stats['malicious'] + analysis_stats['harmless']}"
        
        try:
            detection_timestamp = result['data']['attributes']['last_analysis_date']
            # Convert from UNIX epoch format to datetime object
            dt_obj = datetime.utcfromtimestamp(detection_timestamp)
            # Format to desired string format
            formatted_timestamp = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
        except KeyError:
            print(f"Error: Could not extract last analysis date for domain {domain}")
            return None
        except ValueError:
            print(f"Error: Could not convert last analysis date for domain {domain}")
            return None
        
        domain_status = self.is_domain_live(domain)
        return domain, verdict, detection_ratio, formatted_timestamp, analysis_stats.get('harmless', 0), \
               analysis_stats.get('malicious', 0), analysis_stats.get('suspicious', 0), domain_status


    def generate_report(self, df: pd.DataFrame, output_filename: str) -> None:
        """
        Generate a report based on the DataFrame and save it as a PDF.
        """

        benign_count = len(df[df['Verdict'] == 'Benign'])
        malign_count = len(df[df['Verdict'] == 'Malign'])
        total_count = len(df)
        
        benign_row = pd.DataFrame([['', 'Benign count', f'{benign_count}/{total_count}', '', '', '', '', '']], columns=df.columns)
        malign_row = pd.DataFrame([['', 'Malign count', f'{malign_count}/{total_count}', '', '', '', '', '']], columns=df.columns)
        
        df = pd.concat([df, benign_row, malign_row], ignore_index=True)
        # Adjust the height of the figure based on the number of rows in the DataFrame
        fig_height = len(df) * 0.05
        fig, ax = plt.subplots(figsize=(12, fig_height))
        ax.axis('off')  # Hide axes
        plt.tight_layout(pad=0.1)
        
        colWidths = [
            max(df["Domain"].apply(lambda x: len(x) if x is not None else 0.2) * 0.22) * 0.02 if column == "Domain" 
            else 0.15 if column == "Detection Timestamp" 
            else 0.10 for column in df.columns
        ]
        
        tab = pd.plotting.table(ax, df, loc='upper center', colWidths=colWidths, cellLoc='center', rowLoc='center')
        tab.auto_set_font_size(True) 
        tab.set_fontsize(8)  
        tab.scale(1.2, 1.2)

        # Style adjustments (bold headers, colors based on verdict, hiding index)
        for key, cell in tab.get_celld().items():
            if key[0] == 0 or key[1] == -1:
                cell._text.set_weight('bold')
            if cell.get_text().get_text() == 'Malign':
                cell._text.set_color('red')
            elif cell.get_text().get_text() == 'Benign':
                cell._text.set_color('green')
            if key[1] == -1:
                cell.set_visible(False)
            if key[0] in [total_count+1, total_count+2]:  # Special styling for the benign and malign count rows
                cell._text.set_weight('bold')
                cell.set_facecolor('lightgrey')
            if cell.get_text().get_text() == 'Dead':
                cell._text.set_color('red')
            elif cell.get_text().get_text() == 'Alive':
                cell._text.set_color('green')
        
        # Save the table as a PDF
        plt.savefig(output_filename, bbox_inches='tight', dpi=300)
        plt.close()

if __name__ == "__main__":
    analyzer = DomainAnalyzer()
    #fp domains
    # df = analyzer.process_domains("false_positives/highest_shap.txt")
    # analyzer.generate_report(df, 'false_positives/VT/FP_check.pdf')

    df = analyzer.process_domains("cesnet.txt")
    analyzer.generate_report(df, 'cesnet_udajne_benigni.pdf')
