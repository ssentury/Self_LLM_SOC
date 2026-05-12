import pandas as pd
import json
import yaml
from collections import Counter

csv_path = 'data/sample/regional_care_dynamic_cve_flows_xgb.csv'
manifest_path = 'data/sample/regional_care_dynamic_cve_flows_xgb_manifest.json'

print("="*50)
print("CSV Data Evaluation")
print("="*50)
try:
    df = pd.read_csv(csv_path)
    print(f'Total rows: {len(df)} (Expected: 1000)')
    print(f"Has 'mock_prob' column: {'mock_prob' in df.columns} (Expected: False)")
    print(f"Has 'Label' column: {'Label' in df.columns}")
    print(f"Has 'Attack' column: {'Attack' in df.columns}")
    
    label_counts = df['Label'].value_counts()
    print(f"Benign rows: {label_counts.get('Benign', 0)} (Expected: 900)")
    print(f"Malicious rows: {label_counts.get('Malicious', 0)} (Expected: 100)")
    
    df['timestamp'] = pd.to_datetime(df['FLOW_START_MILLISECONDS'], unit='ms', utc=True)
    df['date'] = df['timestamp'].dt.tz_convert('Asia/Seoul').dt.date
    
    print("\nDaily Flow Counts:")
    daily_counts = df.groupby(['date', 'Label']).size().unstack(fill_value=0)
    for date, row in daily_counts.iterrows():
        print(f"  {date}: Benign: {row.get('Benign', 0)}, Malicious: {row.get('Malicious', 0)} (Total: {row.sum()})")

    print("\nAttack Types:")
    attack_counts = df[df['Label'] == 'Malicious']['Attack'].value_counts()
    for attack, count in attack_counts.items():
        print(f"  {attack}: {count}")

except Exception as e:
    print(f"Error reading CSV: {e}")

print("\n" + "="*50)
print("Manifest Evaluation")
print("="*50)
try:
    with open(manifest_path, 'r', encoding='utf-8') as f:
        manifest_data = json.load(f)
    
    flows = manifest_data.get('source_trace', [])
    print(f'Total manifest flow rows: {len(flows)}')
    
    has_source_index = all('source_index' in row for row in flows)
    print(f"All rows have source_index: {has_source_index}")
    
    # Count overriding
    overrides = manifest_data.get('projection_overrides', [])
    print(f"Port overrides applied: {len(overrides)}")
    if len(overrides) > 0:
        print("  Sample override reason:", overrides[0].get('projection_reason'))
    
    # check scenario specific keys
    keys = Counter([row.get('scenario') for row in flows])
    print("\nTop scenario keys in manifest:")
    for k, v in keys.most_common(10):
        print(f"  {k}: {v}")
        
    print("\nCVE usage in manifest:")
    cve_counts = manifest_data.get('cve_counts', {})
    for k, v in cve_counts.items():
        print(f"  {k}: {v}")

except Exception as e:
    print(f"Error reading Manifest: {e}")

print("\n" + "="*50)
print("YAML Configuration Evaluation")
print("="*50)

def read_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

for day in range(1, 6):
    print(f"\n--- Day {day} ---")
    try:
        base_dir = f'config/scenarios/regional_care_dynamic_cve/generated/day0{day}'
        cve_feed = read_yaml(f'{base_dir}/cve_feed.yaml')
        assets = read_yaml(f'{base_dir}/assets.yaml')
        threat_feed = read_yaml(f'{base_dir}/threat_feed.yaml')
        
        cve_ids = [cve['cve_id'] for cve in cve_feed.get('advisories', [])]
        print(f"Active Advisories: {cve_ids}")
        
        warehouse = next((a for a in assets['assets'] if a['role'] == 'reporting-warehouse'), None)
        if warehouse:
            print(f"reporting-warehouse status: {warehouse.get('status', 'active')}")
        else:
            print("reporting-warehouse not found!")
                
        kiosks = [a for a in assets['assets'] if a['zone'] == 'shared-kiosk-workstations']
        print(f"Shared Kiosk PCs count: {len(kiosks)}")
            
        threat_ips = [t['ip'] for t in threat_feed.get('known_malicious_ips', [])]
        print(f"Has 198.51.100.91 in threat feed: {'198.51.100.91' in threat_ips}")
        
        threat_patterns = [t['name'] for t in threat_feed.get('suspicious_patterns', [])]
        print(f"Threat patterns count: {len(threat_patterns)}")
        if 'tomcat_api_probe_cluster' in threat_patterns:
            print("  Contains 'tomcat_api_probe_cluster'")
        if 'fortimanager_fgfmd_probe' in threat_patterns:
            print("  Contains 'fortimanager_fgfmd_probe'")
            
    except Exception as e:
        print(f"Error reading YAML for Day {day}: {e}")
