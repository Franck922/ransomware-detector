from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class IngestPayload(BaseModel):
    """
    Format attendu lors de l'envoi de logs vers l'endpoint /ingest.
    Accepte une liste d'événements bruts (Winlogbeat) ou pré-normalisés.
    """
    machine_id: str = Field(..., description="L'identifiant de la machine source (ex: VM-WIN10-LAB)")
    batch: List[Dict[str, Any]] = Field(..., description="Liste des événements Sysmon (bruts ou normalisés)")

class ResponseMessage(BaseModel):
    """Format standard pour les réponses simples de l'API"""
    status: str
    message: str
    processed_events: Optional[int] = 0
