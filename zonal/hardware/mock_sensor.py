# zonal/hardware/mock_sensor.py
import random
from .interface import Sensor

class MockNetworkSensor(Sensor):
    def __init__(self, zone_id):
        self.zone_id = zone_id
    def read(self):
        suspicious = random.random() < 0.3
        return {
            "sensor_type": "network",
            "packets_in": random.randint(100, 1000),
            "packets_out": random.randint(50, 500),
            "suspicious_flags": suspicious,
            "threat_score": round(random.uniform(0.5, 1.0), 2) if suspicious else 0.0,
            "details": "Unusual outbound connection detected" if suspicious else "Normal traffic"
        }

class MockFileSensor(Sensor):
    def __init__(self, zone_id):
        self.zone_id = zone_id
    def read(self):
        corrupted = random.random() < 0.2
        return {
            "sensor_type": "file",
            "file_path": f"/home/user/docs/file{random.randint(1,100)}.doc",
            "file_size": random.randint(1024, 102400),
            "corrupted": corrupted,
            "threat_score": 0.9 if corrupted else 0.0,
            "details": "File hash mismatch - possible ransomware" if corrupted else "File integrity OK"
        }

class MockProcessSensor(Sensor):
    def __init__(self, zone_id):
        self.zone_id = zone_id
    def read(self):
        suspicious = random.random() < 0.25
        return {
            "sensor_type": "process",
            "process_name": random.choice(["svchost.exe", "powershell.exe", "cmd.exe", "python.exe"]),
            "cpu_usage": random.randint(0, 100),
            "memory_usage": random.randint(10, 500),
            "suspicious": suspicious,
            "threat_score": 0.8 if suspicious else 0.0,
            "details": "Process injecting code" if suspicious else "Normal process"
        }