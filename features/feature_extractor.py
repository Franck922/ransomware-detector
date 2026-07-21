from typing import List, Dict, Any
from datetime import datetime
import math
import ipaddress
import os

class FeatureExtractor:
    """
    Agrège les événements normalisés sur une fenêtre de temps 
    et calcule les 12 features comportementales.
    Trace également la causalité par processus pour cibler la réponse.
    """
    
    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self.events_buffer: List[Dict[str, Any]] = []
        self.window_start: datetime = None

    def add_event(self, event: Dict[str, Any]) -> bool:
        evt_time_str = event.get("timestamp")
        if not evt_time_str:
            return False
            
        try:
            evt_time = datetime.fromisoformat(evt_time_str.replace("Z", "+00:00"))
        except ValueError:
            return False

        if not self.window_start:
            self.window_start = evt_time

        delta = (evt_time - self.window_start).total_seconds()

        if delta >= self.window_seconds:
            return True

        self.events_buffer.append(event)
        return False

    def extract_features(self) -> Dict[str, Any]:
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
            "nb_dns_queries": 0
        }

        if not self.events_buffer:
            return features

        extensions = set()
        filenames = []
        ips = set()
        
        # Tracking par processus (PID)
        process_tracker = {}

        for event in self.events_buffer:
            action = event.get("action")
            pid = event.get("process_id")
            pname = event.get("process_name", "unknown.exe")
            parent = event.get("parent_process", "unknown.exe")
            parent_pid = event.get("parent_process_id")
            
            # Initialisation du tracker pour ce PID
            if pid and pid not in process_tracker:
                process_tracker[pid] = {
                    "pid": pid,
                    "process_name": pname,
                    "parent_name": parent,
                    "parent_pid": parent_pid,
                    "score": 0,
                    "stats": {
                        "files_created": 0,
                        "files_deleted": 0,
                        "network_connections": 0,
                        "processes_created": 0,
                        "filenames": []
                    }
                }
            
            # --- FILE ACTIVITY (11, 23) ---
            if action == "file_create":
                features["nb_files_created"] += 1
                if pid: 
                    process_tracker[pid]["score"] += 1
                    process_tracker[pid]["stats"]["files_created"] += 1
                
                target = event.get("target_file")
                if target:
                    name = os.path.basename(target)
                    filenames.append(name)
                    if pid: process_tracker[pid]["stats"]["filenames"].append(name)
                    ext = os.path.splitext(name)[1].lower()
                    if ext: extensions.add(ext)
                    
            elif action == "file_delete":
                features["nb_files_deleted"] += 1
                if pid:
                    process_tracker[pid]["score"] += 2
                    process_tracker[pid]["stats"]["files_deleted"] += 1
                
            # --- PROCESS ACTIVITY (1) ---
            elif action == "process_create":
                features["nb_processes_created"] += 1
                parent_name = event.get("parent_process", "")
                if parent_name and "explorer.exe" not in parent_name.lower() and "services.exe" not in parent_name.lower():
                    features["nb_child_processes"] += 1
                    features["process_depth"] = max(features["process_depth"], 2)
                    
                # Le créateur de processus (parent) est suspect
                if parent_pid and parent_pid in process_tracker:
                    process_tracker[parent_pid]["score"] += 2
                    process_tracker[parent_pid]["stats"]["processes_created"] += 1
                elif pid:
                    process_tracker[pid]["score"] += 2
                    process_tracker[pid]["stats"]["processes_created"] += 1

            # --- NETWORK ACTIVITY (3) ---
            elif action == "network_connection":
                features["nb_connections"] += 1
                if pid:
                    process_tracker[pid]["score"] += 2
                    process_tracker[pid]["stats"]["network_connections"] += 1
                    
                ip_str = event.get("network_ip")
                if ip_str:
                    ips.add(ip_str)
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if not ip.is_private and not ip.is_loopback:
                            features["nb_external_connections"] += 1
                    except ValueError:
                        pass

        # Final aggregations globales
        features["nb_unique_extensions"] = len(extensions)
        features["nb_unique_ips"] = len(ips)
        
        if filenames:
            combined_names = "".join(filenames)
            features["entropy_filenames"] = round(self._shannon_entropy(combined_names), 3)
            
        # Extraction du Top Suspect
        top_suspect = None
        max_score = -1
        
        for pid, data in process_tracker.items():
            if data["stats"]["filenames"]:
                combined_p_names = "".join(data["stats"]["filenames"])
                p_entropy = round(self._shannon_entropy(combined_p_names), 3)
                data["stats"]["entropy"] = p_entropy
                if p_entropy > 5.0:
                    data["score"] += 10 # Massive penalty for high entropy
            else:
                data["stats"]["entropy"] = 0.0
                
            if data["score"] > max_score:
                max_score = data["score"]
                top_suspect = data

        if top_suspect:
            # On retire la liste lourde des noms de fichiers pour ne garder que la data agrégée
            top_suspect["stats"].pop("filenames", None)
            features["top_suspect"] = top_suspect

        return features

    def _shannon_entropy(self, data: str) -> float:
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
        self.events_buffer.clear()
        self.window_start = new_start_time
