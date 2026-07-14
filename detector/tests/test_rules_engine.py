import pytest
from detector.rules_engine import RulesEngine

@pytest.fixture
def engine():
    return RulesEngine(alert_threshold=0.80)

def test_normal_behavior(engine):
    # Un utilisateur normal qui navigue et crée 2 fichiers
    features = {
        "nb_files_created": 2,
        "nb_files_deleted": 0,
        "entropy_filenames": 3.2,
        "nb_child_processes": 0
    }
    deviations = {
        "nb_files_created": 0.5,
        "nb_files_deleted": 0.0
    }
    
    result = engine.evaluate(features, deviations)
    
    assert result["alert"] is False
    assert result["risk_score"] == 0.0
    assert len(result["triggered_rules"]) == 0

def test_ransomware_behavior(engine):
    # Simulation d'un ransomware agressif
    features = {
        "nb_files_created": 150,
        "nb_files_deleted": 150,
        "entropy_filenames": 7.9,
        "nb_child_processes": 2
    }
    deviations = {
        "nb_files_created": 12.0, # Z-score massif
        "nb_files_deleted": 15.0  # Z-score massif
    }
    
    result = engine.evaluate(features, deviations)
    
    # Doit déclencher toutes les règles (30 + 30 + 40 + 20 = 120 points, capé à 100)
    assert result["alert"] is True
    assert result["risk_score"] == 1.0
    assert len(result["triggered_rules"]) == 4

def test_partial_suspicious_behavior(engine):
    # Juste une haute entropie (ex: téléchargement d'un gros fichier chiffré par l'utilisateur)
    features = {
        "nb_files_created": 1,
        "nb_files_deleted": 0,
        "entropy_filenames": 5.5,
        "nb_child_processes": 0
    }
    deviations = {
        "nb_files_created": 0.1,
        "nb_files_deleted": 0.0
    }
    
    result = engine.evaluate(features, deviations)
    
    # Déclenche uniquement la Règle 3 (40 points) -> 0.4 de score. Pas d'alerte.
    assert result["alert"] is False
    assert result["risk_score"] == 0.4
    assert len(result["triggered_rules"]) == 1
