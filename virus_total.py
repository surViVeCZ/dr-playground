import vt
from tqdm import tqdm
import pandas as pd
import matplotlib.pyplot as plt
from typing import List, Tuple, Optional


class DomainAnalyzer:
    def __init__(self, api_key: str):
        """
        Initializes the DomainAnalyzer with a VirusTotal API key.
        """
        self.client = vt.Client(api_key)

    def check_domain(self, domain: str) -> Optional[vt.Object]:
        """
        Fetch information for a specific domain.
        """
        try:
            url_id = vt.url_id(domain)
            obj = self.client.get_object(f"/urls/{url_id}")
            self.client.close()
            return obj
        except vt.APIError as e:
            print(f"Error: Unable to fetch information for domain {domain}. {e}")
            return None

    def get_verdict(self, analysis_stats: dict) -> str:
        """
        Determine the verdict of the analysis.
        """
        if analysis_stats.get('malicious', 0) > 0 or analysis_stats.get('suspicious', 0) > 0:
            return "Malign"
        else:
            return "Benign"

    @staticmethod
    def read_domains_from_file(filename: str) -> List[str]:
        """
        Read domains from a given file.
        """
        with open(filename, "r") as file:
            lines = file.readlines()
        return [line.split(",")[0].split(": ")[1] for line in lines]

    def process_domains(self, filename: str) -> pd.DataFrame:
        """
        Process the domains and return a DataFrame with the results.
        """
        domains = self.read_domains_from_file(filename)
        data = []

        for domain in tqdm(domains, desc="Processing domains", unit="domain"):
            result = self.check_domain(domain)
            if result:
                analysis_stats = result.last_analysis_stats
                verdict = self.get_verdict(analysis_stats)
                detection_ratio = f"{analysis_stats['malicious']}/{analysis_stats['malicious'] + analysis_stats['harmless']}"
                detection_timestamp = result.last_analysis_date

                data.append([domain, verdict, detection_ratio, detection_timestamp, analysis_stats.get('harmless', 0),
                             analysis_stats.get('malicious', 0), analysis_stats.get('suspicious', 0)])

        df = pd.DataFrame(data, columns=["Domain", "Verdict", "Detection Ratio", "Detection Timestamp", "Harmless", "Malicious", "Suspicious"])

        return df

    def generate_report(self, df: pd.DataFrame, output_filename: str) -> None:
        """
        Generate a report based on the DataFrame and save it as a PDF.
        """
        # Generate a table from the DataFrame
        fig, ax = plt.subplots(figsize=(12, 4))
        ax.xaxis.set_visible(False)  
        ax.yaxis.set_visible(False)  
        ax.set_frame_on(False)
        
        colWidths = [max(df["Domain"].apply(len)*0.7) * 0.02 if column == "Domain" else 0.15 for column in df.columns]
        
        tab = pd.plotting.table(ax, df, loc='center', colWidths=colWidths, cellLoc='center', rowLoc='center')
        tab.auto_set_font_size(True) 
        tab.set_fontsize(8)  
        tab.scale(1.2, 1.2)
        
        # Adding benign and malign counts as text above the table
        benign_count = len(df[df['Verdict'] == 'Benign'])
        malign_count = len(df[df['Verdict'] == 'Malign'])
        total_count = len(df)
    
        header_text = f"Benign count: {benign_count}/{total_count} ({(benign_count/total_count)*100:.2f}%)\nMalign count: {malign_count}/{total_count} ({(malign_count/total_count)*100:.2f}%)"
        plt.title(header_text, fontsize=10, pad=20)
        
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
        
        # Save the table as a PDF
        plt.savefig(output_filename, bbox_inches='tight', dpi=300)
        plt.close()



if __name__ == "__main__":
    analyzer = DomainAnalyzer('6ba88516f54936e6db7e6813dfe36f21928181b9b19def5d6ce66a489dd4ae96')
    df = analyzer.process_domains("false_positives/highest_shap.txt")
    analyzer.generate_report(df, 'false_positives/FP_check.pdf')
