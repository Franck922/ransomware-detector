import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

def train():
    print("Demarrage de l'entrainement du modele Random Forest...")
    
    # 1. Charger les données
    dataset_path = "../data/processed/dataset.csv"
    if not os.path.exists(dataset_path):
        print(f"Erreur: Le fichier {dataset_path} n'existe pas. Lancez prepare_dataset.py d'abord.")
        return
        
    df = pd.read_csv(dataset_path)
    print(f"Dataset charge : {df.shape[0]} lignes, {df.shape[1]} colonnes.")
    
    # 2. Séparer Features (X) et Label (y)
    X = df.drop('label', axis=1)
    y = df['label']
    
    # 3. Séparation Train / Test (80% / 20%)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # 4. Standardisation des données (Important pour le ML)
    scaler = StandardScaler()
    # On garde les noms de colonnes dans le scaler
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Reconstruire les DataFrames pour garder les noms de colonnes (élimine le warning sklearn)
    X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=X.columns)
    X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=X.columns)
    
    # 5. Entraînement du modèle Random Forest
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    rf_model.fit(X_train_scaled_df, y_train)
    
    # 6. Évaluation
    y_pred = rf_model.predict(X_test_scaled_df)
    print("\nEvaluation sur les donnees de test :")
    print(classification_report(y_test, y_pred))
    print("Matrice de confusion :")
    print(confusion_matrix(y_test, y_pred))
    
    # 7. Sauvegarde des modèles
    os.makedirs("../models", exist_ok=True)
    joblib.dump(rf_model, "../models/random_forest_model.pkl")
    joblib.dump(scaler, "../models/scaler.pkl")
    
    print("\nModeles sauvegardes avec succes dans le dossier 'models/' !")

if __name__ == "__main__":
    train()
