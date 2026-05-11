import pandas as pd
import json

try:
    df = pd.read_csv('data/sample/clinic_telehealth_flows_xgb.csv')

    print('=== Null Values Check ===')
    null_counts = df.isnull().sum()
    print(null_counts[null_counts > 0])

    print('\n=== Protocol Validity ===')
    if 'PROTOCOL' in df.columns:
        print(df['PROTOCOL'].value_counts())

    print('\n=== Timestamp Range ===')
    if 'FLOW_START_MILLISECONDS' in df.columns:
        start_ts = df['FLOW_START_MILLISECONDS'].min()
        end_ts = df['FLOW_START_MILLISECONDS'].max()
        print('Start:', pd.to_datetime(start_ts, unit='ms'))
        print('End:', pd.to_datetime(end_ts, unit='ms'))

    print('\n=== Comparing with Non-XGB version ===')
    try:
        df_raw = pd.read_csv('data/sample/clinic_telehealth_flows.csv')
        print('Raw shape:', df_raw.shape)
        print('Raw label dist:')
        if 'category' in df_raw.columns:
            print(df_raw['category'].value_counts())
        elif 'Label' in df_raw.columns:
             print(df_raw['Label'].value_counts())
        else:
            print('No category/Label col')
    except Exception as e:
        print('No raw file or error:', e)
except Exception as e:
    print('Error:', e)
