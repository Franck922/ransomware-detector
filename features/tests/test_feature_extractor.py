import pytest
from features.feature_extractor import FeatureExtractor

@pytest.fixture
def extractor():
    return FeatureExtractor(window_seconds=10)

def test_feature_extraction_file_activity(extractor):
    # Simulate first event starting the window
    evt1 = {
        "event_id": 11,
        "timestamp": "2026-07-06T14:10:00.000Z",
        "action": "file_create",
        "target_file": "C:\\doc1.txt"
    }
    
    evt2 = {
        "event_id": 11,
        "timestamp": "2026-07-06T14:10:02.000Z",
        "action": "file_create",
        "target_file": "C:\\doc2.pdf"
    }
    
    evt3 = {
        "event_id": 23,
        "timestamp": "2026-07-06T14:10:05.000Z",
        "action": "file_delete",
        "target_file": "C:\\doc1.txt"
    }
    
    assert extractor.add_event(evt1) is False
    assert extractor.add_event(evt2) is False
    assert extractor.add_event(evt3) is False
    
    features = extractor.extract_features()
    
    assert features["nb_files_created"] == 2
    assert features["nb_files_deleted"] == 1
    assert features["nb_unique_extensions"] == 2  # .txt and .pdf
    assert features["entropy_filenames"] > 0.0

def test_window_overflow(extractor):
    # Event exactly at 0s
    evt1 = {"timestamp": "2026-07-06T14:10:00.000Z", "action": "file_create"}
    # Event at +5s
    evt2 = {"timestamp": "2026-07-06T14:10:05.000Z", "action": "file_create"}
    # Event at +11s (should trigger window full)
    evt3 = {"timestamp": "2026-07-06T14:10:11.000Z", "action": "file_create"}
    
    assert extractor.add_event(evt1) is False
    assert extractor.add_event(evt2) is False
    assert extractor.add_event(evt3) is True # Indicates time to extract and reset

def test_network_and_process_features(extractor):
    evt1 = {
        "timestamp": "2026-07-06T14:10:00.000Z",
        "action": "network_connection",
        "network_ip": "8.8.8.8"
    }
    evt2 = {
        "timestamp": "2026-07-06T14:10:01.000Z",
        "action": "network_connection",
        "network_ip": "192.168.1.10" # Private IP
    }
    evt3 = {
        "timestamp": "2026-07-06T14:10:02.000Z",
        "action": "process_create",
        "parent_process": "cmd.exe" # Not explorer or services -> child process
    }
    
    extractor.add_event(evt1)
    extractor.add_event(evt2)
    extractor.add_event(evt3)
    
    features = extractor.extract_features()
    
    assert features["nb_connections"] == 2
    assert features["nb_unique_ips"] == 2
    assert features["nb_external_connections"] == 1 # Only 8.8.8.8 is external
    assert features["nb_processes_created"] == 1
    assert features["nb_child_processes"] == 1
    assert features["process_depth"] == 2
