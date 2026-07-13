from typing import List, Dict, Any
from datetime import datetime
import math
import ipaddress
import os

class FeatureExtractor:
    """
    Agrège les événements normalisés sur une fenêtre de temps 
    et calcule les 12 features comportementales.
    """
    
    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self.events_buffer: List[Dict[str, Any]] = []
        self.window_start: datetime = None

    def add_event(self, event: Dict[str, Any]) -> bool:
        """
        Ajoute un événement au buffer. 
        Retourne True si la fenêtre est pleine (doit être extraite), False sinon.
        """
        evt_time_str = event.get("timestamp")
        if not evt_time_str:
            return False
            
        # Parse timestamp (Winlogbeat format: 2026-07-06T14:06:09.012Z)
        try:
            # Handle standard ISO format parsing (stripping Z)
            evt_time = datetime.fromisoformat(evt_time_str.replace("Z", "+00:00"))
        except ValueError:
            return False

        if not self.window_start:
            self.window_start = evt_time

        delta = (evt_time - self.window_start).total_seconds()

        if delta >= self.window_seconds:
            return True # Window is full, caller should extract features and reset

        self.events_buffer.append(event)
        return False

    def extract_features(self) -> Dict[str, Any]:
        """
        Calcule et retourne les 12 features pour la fenêtre temporelle actuelle.
        """
        features = {
            "nb_files_created": 0,
            "nb_files_deleted": 0,
            "nb_files_renamed": 0,
            "nb_unique_extensions": 0,
            "entropy_filenames": 0.0,
            "nb_processes_created": 0,
            "nb_child_processes": 0,
            "process_depth": 0,
            "nb_connections": 0,
            "nb_unique_ips": 0,
            "nb_external_connections": 0,
            "nb_dns_queries": 0 # Sysmon Event 22 non collecté par défaut, reste à 0
        }

        if not self.events_buffer:
            return features

        extensions = set()
        filenames = []
        ips = set()
        
        for event in self.events_buffer:
            action = event.get("action")
            
            # --- FILE ACTIVITY (11, 23) ---
            if action == "file_create":
                features["nb_files_created"] += 1
                target = event.get("target_file")
                if target:
                    name = os.path.basename(target)
                    filenames.append(name)
                    ext = os.path.splitext(name)[1].lower()
                    if ext: extensions.add(ext)
                    
            elif action == "file_delete":
                features["nb_files_deleted"] += 1
                
            # Note: Renamed files (Sysmon Event 2) are not in our filter, 
            # so we keep it at 0 for this MVP, or infer it if file_create + file_delete match.
                
            # --- PROCESS ACTIVITY (1) ---
            elif action == "process_create":
                features["nb_processes_created"] += 1
                parent = event.get("parent_process")
                if parent and "explorer.exe" not in parent.lower() and "services.exe" not in parent.lower():
                    # Heuristique basique : si ce n'est pas un processus système standard
                    features["nb_child_processes"] += 1
                    features["process_depth"] = max(features["process_depth"], 2) # Simplification MVP

            # --- NETWORK ACTIVITY (3) ---
            elif action == "network_connection":
                features["nb_connections"] += 1
                ip_str = event.get("network_ip")
                if ip_str:
                    ips.add(ip_str)
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if not ip.is_private and not ip.is_loopback:
                            features["nb_external_connections"] += 1
                    except ValueError:
                        pass

        # Final aggregations
        features["nb_unique_extensions"] = len(extensions)
        features["nb_unique_ips"] = len(ips)
        
        # Calculate Shannon entropy for all created filenames
        if filenames:
            combined_names = "".join(filenames)
            features["entropy_filenames"] = round(self._shannon_entropy(combined_names), 3)

        return features

    def _shannon_entropy(self, data: str) -> float:
        """Calcule l'entropie de Shannon d'une chaîne de caractères (0.0 = prévisible, ~8.0 = aléatoire/chiffré)"""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
            
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy

    def reset_window(self, new_start_time: datetime = None):
        """Réinitialise le buffer pour la prochaine fenêtre temporelle."""
        self.events_buffer.clear()
        self.window_start = new_start_time
