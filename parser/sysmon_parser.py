import json
from typing import Dict, Any, Optional
from datetime import datetime

class SysmonParser:
    """
    Parser for Winlogbeat JSON events containing Sysmon data.
    Filters out noise and normalizes relevant events (1, 3, 11, 23) into a standard format.
    """
    
    # Event IDs relevant for ransomware detection
    # 1: Process Creation
    # 3: Network Connection
    # 11: File Create
    # 23: File Delete
    RELEVANT_EVENT_IDS = {1, 3, 11, 23}

    def __init__(self):
        pass

    def parse_event(self, raw_event_json: str | Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parses a raw Winlogbeat JSON string or dict.
        Returns a normalized dictionary if the event is relevant, else None.
        """
        try:
            if isinstance(raw_event_json, str):
                event = json.loads(raw_event_json)
            else:
                event = raw_event_json
                
            # Check if it's a valid winlogbeat event with an event_id
            winlog = event.get("winlog", {})
            event_id_str = winlog.get("event_id")
            
            if not event_id_str:
                return None
                
            event_id = int(event_id_str)
            
            if event_id not in self.RELEVANT_EVENT_IDS:
                return None
                
            return self._normalize(event, event_id)
            
        except (json.JSONDecodeError, ValueError, AttributeError, TypeError) as e:
            # Silently ignore malformed logs for robustness
            return None

    def _normalize(self, event: Dict[str, Any], event_id: int) -> Dict[str, Any]:
        """
        Normalizes a relevant Sysmon event into the standard dictionary format.
        """
        winlog = event.get("winlog", {})
        event_data = winlog.get("event_data", {})
        
        # Base normalized event structure
        normalized = {
            "event_id": event_id,
            "timestamp": event.get("@timestamp"),
            "process_name": None,
            "process_id": None,
            "process_path": None,
            "parent_process": None,
            "parent_process_id": None,
            "target_file": None,
            "action": None,
            "network_ip": None,
            "network_port": None
        }

        # Common extraction (Process)
        # Image is usually the full path
        process_path = event_data.get("Image")
        if process_path:
            normalized["process_path"] = process_path
            normalized["process_name"] = process_path.split("\\")[-1] if "\\" in process_path else process_path

        pid = event_data.get("ProcessId")
        if pid:
            try:
                normalized["process_id"] = int(pid)
            except ValueError:
                pass

        parent_path = event_data.get("ParentImage")
        if parent_path:
            normalized["parent_process"] = parent_path.split("\\")[-1] if "\\" in parent_path else parent_path
            
        parent_pid = event_data.get("ParentProcessId")
        if parent_pid:
            try:
                normalized["parent_process_id"] = int(parent_pid)
            except ValueError:
                pass

        # Event-specific extraction
        if event_id == 1:
            normalized["action"] = "process_create"
            
        elif event_id == 3:
            normalized["action"] = "network_connection"
            normalized["network_ip"] = event_data.get("DestinationIp")
            port = event_data.get("DestinationPort")
            if port:
                try:
                    normalized["network_port"] = int(port)
                except ValueError:
                    pass
                    
        elif event_id == 11:
            normalized["action"] = "file_create"
            normalized["target_file"] = event_data.get("TargetFilename")
            
        elif event_id == 23:
            normalized["action"] = "file_delete"
            normalized["target_file"] = event_data.get("TargetFilename")

        return normalized

