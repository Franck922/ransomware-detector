import pytest
from parser.sysmon_parser import SysmonParser

@pytest.fixture
def parser():
    return SysmonParser()

def test_parse_event_1_process_create(parser):
    raw_event = {
        "@timestamp": "2026-07-06T14:06:09.012Z",
        "winlog": {
            "event_id": "1",
            "event_data": {
                "ProcessId": "1964",
                "Image": "C:\\Program Files\\Winlogbeat\\winlogbeat.exe",
                "ParentImage": "C:\\Windows\\System32\\services.exe"
            }
        }
    }
    result = parser.parse_event(raw_event)
    
    assert result is not None
    assert result["event_id"] == 1
    assert result["action"] == "process_create"
    assert result["process_id"] == 1964
    assert result["process_name"] == "winlogbeat.exe"
    assert result["process_path"] == "C:\\Program Files\\Winlogbeat\\winlogbeat.exe"
    assert result["parent_process"] == "services.exe"
    assert result["target_file"] is None

def test_parse_event_11_file_create(parser):
    raw_event = {
        "@timestamp": "2026-07-06T14:10:00.000Z",
        "winlog": {
            "event_id": "11",
            "event_data": {
                "ProcessId": "4821",
                "Image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\unknown.exe",
                "TargetFilename": "C:\\Users\\Admin\\Documents\\rapport.docx.encrypted"
            }
        }
    }
    result = parser.parse_event(raw_event)
    
    assert result is not None
    assert result["event_id"] == 11
    assert result["action"] == "file_create"
    assert result["process_id"] == 4821
    assert result["process_name"] == "unknown.exe"
    assert result["target_file"] == "C:\\Users\\Admin\\Documents\\rapport.docx.encrypted"

def test_ignore_irrelevant_event(parser):
    # Event ID 5 (Process Terminated) which we don't care about according to specs
    raw_event = {
        "@timestamp": "2026-07-06T14:10:00.000Z",
        "winlog": {
            "event_id": "5",
            "event_data": {
                "ProcessId": "4821",
                "Image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\unknown.exe"
            }
        }
    }
    result = parser.parse_event(raw_event)
    assert result is None
