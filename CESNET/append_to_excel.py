import sys
import pandas as pd
from openpyxl import load_workbook

def append_to_excel(csv_file_path, excel_file_path):
    # Read domains from CSV
    df_csv = pd.read_csv(csv_file_path, usecols=['DOMAIN'])

    # Load the existing Excel file or create a new one if it doesn't exist
    try:
        with pd.ExcelWriter(excel_file_path, engine='openpyxl', mode='a') as writer:
            df_csv.to_excel(writer, sheet_name='Sheet1', startrow=writer.sheets['Sheet1'].max_row, index=False, header=False)
    except FileNotFoundError:
        df_csv.to_excel(excel_file_path, sheet_name='Sheet1', index=False, header=True)

# Get the CSV file path and the output Excel file from the command line arguments
csv_file_path = sys.argv[1]
excel_file_path = sys.argv[2]

#create main
def main():
    append_to_excel(csv_file_path, excel_file_path)
