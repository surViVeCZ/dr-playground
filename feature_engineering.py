import nbformat
from nbconvert.preprocessors import ExecutePreprocessor

def run_notebook_and_extract_fp(notebook_path, feature):
    # Load the notebook
    with open(notebook_path, 'r', encoding='utf-8') as f:
        notebook_content = f.read()
    
    # Parse the notebook content
    notebook = nbformat.reads(notebook_content, as_version=4)
    
    # Modify the feature_to_drop cell
    for cell in notebook.cells:
        if cell.source.startswith("feature_to_drop"):
            cell.source = f'feature_to_drop = "{feature}"'
            break

    # Execute the notebook
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(notebook, {'metadata': {'path': './'}})

    # Extract the false positives value
    # Assuming the last cell contains the value we want to extract
    last_cell_output = notebook.cells[-1].outputs[0].text
    return last_cell_output

# List of features to drop
features_to_drop = ['rdap_domain_age', 'tls_root_cert_lifetime', 'rdap_domain_active_time', 'rdap_time_from_last_change']  

# Dictionary to store false positives for each feature
fp_values = {}

# Execute the notebook for each feature
for feature in features_to_drop:
    fp_value = run_notebook_and_extract_fp('Playground.ipynb', feature)
    fp_values[feature] = fp_value

print(fp_values)
