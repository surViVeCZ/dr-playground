import os
import subprocess
from typing import List, Tuple, Optional

import vt
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
from dotenv import load_dotenv


class DomainAnalyzer:
    def __init__(self):
        """
        Initializes the DomainAnalyzer with a VirusTotal API key loaded from an environment variable.
        """
        self.client = self.initialize_client()

    @staticmethod
    def initialize_client():
        """
        Load API key and initialize the vt.Client.
        """
        load_dotenv()  # Load environment variables from .env file
        api_key = os.getenv('VT_API_KEY')  # Get the API key from the environment variable

        if api_key is None:
            raise ValueError("API key is not set. Please set the VT_API_KEY environment variable.")

        return vt.Client(api_key)
        
    @staticmethod
    def read_domains_from_file(filename: str) -> List[str]:
        """
        Read domains from a given file.
        """
        with open(filename, "r") as file:
            lines = file.readlines()
        return [line.split(",")[0].split(": ")[1] for line in lines]

    def check_domain(self, domain: str) -> Optional[vt.Object]:
        """
        Fetch information for a specific domain.
        """
        try:
            url_id = vt.url_id(domain)
            obj = self.client.get_object(f"/urls/{url_id}")
            return obj
        except vt.APIError as e:
            print(f"Error: Unable to fetch information for domain {domain}. {e}")
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
        """
        Process the domains and return a DataFrame with the results.
        """
        domains = self.read_domains_from_file(filename)
        data = []

        for domain in tqdm(domains, desc="Processing domains", unit="domain"):
            result = self.check_domain(domain)
            if result:
                data.append(self.extract_domain_data(domain, result))

        columns = ["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious", "Live Status"]
        df = pd.DataFrame(data, columns=columns)

        # Sorting the DataFrame by Verdict and Live Status columns
        df.sort_values(by=['Verdict', 'Live Status'], ascending=[False, False], inplace=True)
        
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
        
    def extract_domain_data(self, domain: str, result: vt.Object) -> Tuple:
        """
        Extract necessary data from the domain result.
        """
        analysis_stats = result.last_analysis_stats
        verdict = self.get_verdict(analysis_stats)
        detection_ratio = f"{analysis_stats['malicious']}/{analysis_stats['malicious'] + analysis_stats['harmless']}"
        detection_timestamp = result.last_analysis_date
        domain_status = self.is_domain_live(domain)
        return domain, verdict, detection_ratio, detection_timestamp, analysis_stats.get('harmless', 0), \
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
        fig_height = len(df) * 0.2
        fig, ax = plt.subplots(figsize=(12, fig_height))
        ax.axis('off')  # Hide axes
        
        colWidths = [max(df["Domain"].apply(len)*0.7) * 0.02 if column == "Domain" else 0.15 for column in df.columns]
        
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
    df = analyzer.process_domains("false_positives/highest_shap.txt")
    analyzer.generate_report(df, 'false_positives/FP_check.pdf')
    analyzer.client.close()
