import re
import ast
import yaml

def parse_custom_csv(csv_filepath):
    data_list = []
    
    # This regex matches either:
    # 1. Anything inside brackets [...]
    # 2. Anything inside double quotes "..."
    # 3. Anything else between commas
    pattern = re.compile(r'(\[[^\]]*\]|"[^"]*"|[^,]+)')

    with open(csv_filepath, mode="r", encoding="utf-8") as f:
        # Read headers
        headers = [h.strip() for h in f.readline().strip().split(",")]
        
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            # Find all matched columns ignoring commas inside brackets/quotes
            row_values = pattern.findall(line)
            
            # Clean up outer quotes if present
            row_values = [val.strip().strip('"') for val in row_values]
            
            # Build row dictionary mapping headers to row values
            row = dict(zip(headers, row_values))
            
            # 1. Clean up Integers
            if "vlan_id" in row and row["vlan_id"].isdigit():
                row["vlan_id"] = int(row["vlan_id"])
                
            # 2. Safe parse lists using ast.literal_eval
            list_columns = ["vmware_domains", "nutanix_domains", "physical_domains"]
            for col in list_columns:
                if col in row and row[col].startswith("["):
                    try:
                        row[col] = ast.literal_eval(row[col])
                    except (ValueError, SyntaxError):
                        row[col] = []
                else:
                    row[col] = []
                    
            data_list.append(row)
            
    return data_list

def convert_csv_to_yaml(csv_filepath, yaml_filepath):
    # Parse using our custom regex parser
    data_list = parse_custom_csv(csv_filepath)
    
    # Save to yaml
    with open(yaml_filepath, mode="w", encoding="utf-8") as yaml_file:
        yaml.dump(data_list, yaml_file, sort_keys=False, default_flow_style=False)
        
    print(f"Success! Converted '{csv_filepath}' to '{yaml_filepath}' with zero null fields.")

# Run it
convert_csv_to_yaml("input.csv", "output.yaml")

