import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
import sys

# Ajouter le répertoire parent au path pour pouvoir importer parser et features
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parser.sysmon_parser import SysmonParser
from features.feature_extractor import FeatureExtractor

def process_winlogbeat_baseline(filepath):
    print(f"Traitement de la baseline système : {filepath}")
    parser = SysmonParser()
    extractor = FeatureExtractor(window_seconds=10)
    vectors = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                raw_event = json.loads(line)
                parsed_event = parser.parse_event(raw_event)
                if parsed_event:
                    if extractor.add_event(parsed_event):
                        # La fenêtre de 10s est pleine
                        features = extractor.extract_features()
                        features['label'] = 0
                        vectors.append(features)
                        # Démarrer une nouvelle fenêtre
                        evt_time = datetime.fromisoformat(parsed_event['timestamp'].replace("Z", "+00:00"))
                        extractor.reset_window(evt_time)
                        extractor.add_event(parsed_event)
            except Exception as e:
                pass
    
    # Extraire la dernière fenêtre s'il reste des événements
    if extractor.events_buffer:
        features = extractor.extract_features()
        features['label'] = 0
        vectors.append(features)
        
    return pd.DataFrame(vectors)

def process_zeek_baseline(filepath):
    print(f"Traitement de la baseline réseau : {filepath}")
    df = pd.read_csv(filepath)
    df['datetime'] = pd.to_datetime(df['datetime'])
    df.set_index('datetime', inplace=True)
    
    # Resampler par tranches de 10 secondes
    resampled = df.resample('10S').agg(
        nb_connections=('dest_ip', 'count'),
        nb_unique_ips=('dest_ip', 'nunique'),
        nb_dns_queries=('service', lambda x: (x == 'dns').sum())
    )
    # Ne garder que les fenêtres avec de l'activité
    resampled = resampled[resampled['nb_connections'] > 0].copy()
    
    # Ajouter les features système (valeurs normales aléatoires basses)
    resampled['nb_files_created'] = np.random.randint(0, 3, size=len(resampled))
    resampled['nb_files_deleted'] = 0
    resampled['nb_files_renamed'] = 0
    resampled['nb_unique_extensions'] = np.random.randint(0, 2, size=len(resampled))
    resampled['entropy_filenames'] = np.random.uniform(0.0, 3.5, size=len(resampled))
    resampled['nb_processes_created'] = np.random.randint(0, 2, size=len(resampled))
    resampled['nb_child_processes'] = 0
    resampled['process_depth'] = 1
    resampled['nb_external_connections'] = resampled['nb_connections'] // 2
    resampled['label'] = 0
    
    return resampled.reset_index(drop=True)

def process_stratosphere_malware(filepaths):
    frames = []
    for filepath in filepaths:
        print(f"Traitement du malware réseau : {filepath}")
        df = pd.read_csv(filepath)
        df['StartTime'] = pd.to_datetime(df['StartTime'])
        df.set_index('StartTime', inplace=True)
        
        resampled = df.resample('10S').agg(
            nb_connections=('DstAddr', 'count'),
            nb_unique_ips=('DstAddr', 'nunique')
        )
        resampled = resampled[resampled['nb_connections'] > 0].copy()
        
        # Synthétiser les comportements d'un ransomware en action
        resampled['nb_files_created'] = np.random.randint(50, 200, size=len(resampled))
        resampled['nb_files_deleted'] = np.random.randint(0, 50, size=len(resampled))
        resampled['nb_files_renamed'] = np.random.randint(10, 100, size=len(resampled))
        resampled['nb_unique_extensions'] = np.random.randint(5, 15, size=len(resampled))
        resampled['entropy_filenames'] = np.random.uniform(5.0, 7.5, size=len(resampled))
        resampled['nb_processes_created'] = np.random.randint(5, 20, size=len(resampled))
        resampled['nb_child_processes'] = np.random.randint(2, 10, size=len(resampled))
        resampled['process_depth'] = np.random.randint(3, 6, size=len(resampled))
        resampled['nb_external_connections'] = resampled['nb_connections']
        resampled['nb_dns_queries'] = np.random.randint(0, 10, size=len(resampled))
        resampled['label'] = 1
        
        frames.append(resampled.reset_index(drop=True))
        
    return pd.concat(frames, ignore_index=True)

if __name__ == "__main__":
    print("Démarrage de la préparation du dataset...")
    
    # 1. Baseline système (Nos propres logs de la VM)
    df_sys_baseline = process_winlogbeat_baseline("../data/raw/winlogbeat-output-20260706.ndjson")
    
    # 2. Baseline réseau (UWF-ZeekData22)
    df_net_baseline = process_zeek_baseline("../data/external/part-00000-0af89d10-df53-44fd-b124-a8a496fd5023-c000.csv")
    
    # 3. Ransomware (Stratosphere + features système synthétiques)
    malware_files = [
        "../data/external/2017-05-15_win7.binetflow.txt",
        "../data/external/2017-07-11_capture-win2.binetflow.txt",
        "../data/external/2015-10-11_win3.binetflow.txt"
    ]
    df_malware = process_stratosphere_malware(malware_files)
    
    # 4. Fusion des 3 sources
    final_df = pd.concat([df_sys_baseline, df_net_baseline, df_malware], ignore_index=True)
    
    # 5. Mélanger les lignes (Shuffle)
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # 6. Ordonner les colonnes pour s'assurer que c'est propre
    cols = ['nb_files_created', 'nb_files_deleted', 'nb_files_renamed', 'nb_unique_extensions',
            'entropy_filenames', 'nb_processes_created', 'nb_child_processes', 'process_depth',
            'nb_connections', 'nb_unique_ips', 'nb_external_connections', 'nb_dns_queries', 'label']
    
    for c in cols:
        if c not in final_df.columns:
            final_df[c] = 0
            
    final_df = final_df[cols]
    
    # 7. Sauvegarde dans le dossier processed
    os.makedirs("../data/processed", exist_ok=True)
    final_df.to_csv("../data/processed/dataset.csv", index=False)
    
    print(f"\nDataset final généré avec succès ! Shape: {final_df.shape}")
    print("\nDistribution des labels :")
    print(final_df['label'].value_counts())
