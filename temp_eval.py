import pandas as pd
import json

try:
    df = pd.read_csv('data/sample/clinic_telehealth_flows_xgb.csv')
    print('=== Dataset Shape ===')
    print(df.shape)

    print('\n=== Columns ===')
    print(df.columns.tolist()[:10], '...', df.columns.tolist()[-10:])

    print('\n=== Label Distribution ===')
    if 'Label' in df.columns:
        print(df['Label'].value_counts())
    if 'Attack' in df.columns:
        print(df['Attack'].value_counts())

    print('\n=== IP and Port Context (Attacks) ===')
    if 'IPV4_SRC_ADDR' in df.columns and 'Label' in df.columns:
        attacks = df[df['Label'] == 1] if df['Label'].dtype == 'int64' else df[df['Label'] != 'Benign']
        print(attacks[['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 'Attack']].drop_duplicates().head(30))

    print('\n=== Feature Stats (Attack vs Benign) ===')
    features_to_check = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS', 'TCP_FLAGS']
    existing_features = [f for f in features_to_check if f in df.columns]
    if existing_features and 'Label' in df.columns:
        print(df.groupby('Label')[existing_features].mean())

    print('\n=== Time Order Check ===')
    if 'FLOW_START_MILLISECONDS' in df.columns:
        print('FLOW_START_MILLISECONDS is monotonic increasing:', df['FLOW_START_MILLISECONDS'].is_monotonic_increasing)
        print(df['FLOW_START_MILLISECONDS'].head())
except Exception as e:
    print(f"Error: {e}")
