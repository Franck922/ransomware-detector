import numpy as np
from typing import Dict, List, Any
import logging

logger = logging.getLogger("baseline")

class BaselineEngine:
    """
    Moteur de calcul de la baseline (comportement normal).
    Observe les features sur une période (ex: 15 minutes), puis calcule 
    la moyenne et l'écart-type pour évaluer les déviations futures.
    """
    
    def __init__(self, min_vectors: int = 90):
        """
        Args:
            min_vectors: Nombre minimum de vecteurs à collecter avant de calculer la baseline.
                         Par défaut 90 fenêtres de 10s = 15 minutes d'observation.
        """
        # Stocke l'historique des features pendant la phase d'apprentissage
        self.history: List[Dict[str, float]] = []
        self.min_vectors = min_vectors
        
        # Moyennes (mu) et écarts-types (sigma) calculés
        self.means: Dict[str, float] = {}
        self.stds: Dict[str, float] = {}
        
        self.is_trained = False

    def add_vector(self, features: Dict[str, float]):
        """
        Ajoute un vecteur de features à l'historique (pendant l'apprentissage).
        Déclenche automatiquement le calcul de la baseline quand assez de données sont collectées.
        """
        if not self.is_trained:
            self.history.append(features)
            logger.info(f"📊 Baseline : apprentissage en cours ({len(self.history)}/{self.min_vectors} vecteurs)")
            
            if len(self.history) >= self.min_vectors:
                self.compute_baseline()
                logger.info("✅ Baseline calculée ! Le système passe en mode DÉTECTION.")

    def compute_baseline(self):
        """
        Calcule la moyenne et l'écart-type pour chaque feature 
        à partir de l'historique collecté.
        """
        if not self.history:
            logger.warning("Impossible de calculer la baseline : historique vide.")
            return

        # Récupère le nom de toutes les features depuis le premier dictionnaire
        # On filtre les clés non-numériques (ex: top_suspect qui est un dict)
        feature_keys = [k for k in self.history[0].keys() 
                        if isinstance(self.history[0][k], (int, float))]
        
        for key in feature_keys:
            # Extrait toutes les valeurs pour cette feature spécifique
            values = [vector.get(key, 0.0) for vector in self.history]
            
            # Calcul numpy (très rapide)
            self.means[key] = float(np.mean(values))
            # On impose un écart-type minimum de 1.0 pour éviter les Z-scores astronomiques (division par zéro)
            self.stds[key] = max(float(np.std(values)), 1.0)
            
        self.is_trained = True
        logger.info(f"Baseline calculée sur {len(self.history)} fenêtres de temps.")

    def get_deviations(self, current_features: Dict[str, float]) -> Dict[str, float]:
        """
        Prend un nouveau vecteur de features et calcule son écart (Z-Score)
        par rapport à la baseline. (Combien d'écarts-types au-dessus de la normale)
        """
        if not self.is_trained:
            logger.warning("Baseline non calculée. Déviations retournées à 0.")
            return {k: 0.0 for k in current_features.keys()}

        deviations = {}
        for key, value in current_features.items():
            # On ignore les clés non-numériques (ex: top_suspect)
            if not isinstance(value, (int, float)):
                continue
                
            mean = self.means.get(key, 0.0)
            std = self.stds.get(key, 1e-6)
            
            # Z-Score : (Valeur - Moyenne) / Ecart-type
            # Si z_score est positif, l'activité est supérieure à la normale
            z_score = (value - mean) / std
            
            # On ne s'intéresse qu'aux pics anormaux (activités en augmentation)
            # donc on peut clipper à 0 les valeurs négatives si on veut, 
            # mais gardons la valeur absolue ou brute pour le moment
            deviations[key] = round(float(z_score), 2)
            
        return deviations
