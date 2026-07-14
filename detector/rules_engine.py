from typing import Dict, Any, Tuple, List
import logging

logger = logging.getLogger("rules_engine")

class RulesEngine:
    """
    Moteur de détection heuristique basé sur 4 règles comportementales.
    Retourne un score de risque (0.0 à 1.0) et lève une alerte si > 0.80.
    """

    def __init__(self, alert_threshold: float = 0.80):
        self.alert_threshold = alert_threshold

    def evaluate(self, features: Dict[str, Any], deviations: Dict[str, float]) -> Dict[str, Any]:
        """
        Évalue le vecteur de features de 10s et les déviations par rapport au baseline.
        """
        score_points = 0
        triggered_rules = []
        
        # Extraction des valeurs
        files_created = features.get("nb_files_created", 0)
        files_deleted = features.get("nb_files_deleted", 0)
        entropy = features.get("entropy_filenames", 0.0)
        child_procs = features.get("nb_child_processes", 0)
        
        dev_created = deviations.get("nb_files_created", 0.0)
        dev_deleted = deviations.get("nb_files_deleted", 0.0)

        # ---------------------------------------------------------
        # REGLE 1 : Vitesse de création (Création massive)
        # ---------------------------------------------------------
        # Si + de 30 fichiers créés ET que c'est très anormal (Z-Score > 3.0)
        if files_created > 30 and dev_created > 3.0:
            points = 30
            score_points += points
            triggered_rules.append(f"Création massive de fichiers (>{files_created} en 10s) (+{points}pts)")

        # ---------------------------------------------------------
        # REGLE 2 : Destruction des preuves (Suppression massive)
        # ---------------------------------------------------------
        # Si + de 30 fichiers supprimés ET que c'est anormal (Z-Score > 3.0)
        if files_deleted > 30 and dev_deleted > 3.0:
            points = 30
            score_points += points
            triggered_rules.append(f"Suppression massive de fichiers (>{files_deleted} en 10s) (+{points}pts)")

        # ---------------------------------------------------------
        # REGLE 3 : Signature du chiffrement (Haute Entropie)
        # ---------------------------------------------------------
        # Seuil calibré à 5.0 (Shannon entropy pour noms aléatoires alphanumériques ≈ 5.5)
        # Noms de fichiers normaux (rapport_2026.docx) ont une entropie ≈ 3.0-3.5
        if files_created > 0 and entropy > 5.0:
            points = 40
            score_points += points
            triggered_rules.append(f"Entropie suspecte détectée ({entropy} > 5.0) (+{points}pts)")

        # ---------------------------------------------------------
        # REGLE 4 : Comportement des processus suspects
        # ---------------------------------------------------------
        # Si un processus non standard apparaît PENDANT une forte activité fichier
        if child_procs > 0 and (files_created > 10 or files_deleted > 10):
            points = 20
            score_points += points
            triggered_rules.append(f"Processus enfant suspect avec activité fichier (+{points}pts)")

        # ---------------------------------------------------------
        # Calcul du score final
        # ---------------------------------------------------------
        # Score maximum capé à 100 points
        final_points = min(score_points, 100)
        
        # Conversion en float de 0.0 à 1.0
        risk_score = final_points / 100.0
        
        # Déclenchement de l'alerte
        is_alert = risk_score >= self.alert_threshold
        
        if is_alert:
            logger.warning(f"🚨 ALERTE RANSOMWARE ! Score: {risk_score} - Règles: {triggered_rules}")
            
        return {
            "risk_score": risk_score,
            "alert": is_alert,
            "model_used": "rules_engine",
            "triggered_rules": triggered_rules,
            "top_features": {
                "nb_files_created": files_created,
                "nb_files_deleted": files_deleted,
                "entropy_filenames": entropy
            }
        }
