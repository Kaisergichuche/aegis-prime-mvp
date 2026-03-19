# zonal/detector.py
from common.models import ThreatEvent, ZonalReport
from zonal.hardware.mock_sensor import MockNetworkSensor, MockFileSensor, MockProcessSensor

class LocalDetector:
    def __init__(self, zone_id: str, sensor_type: str):
        self.zone_id = zone_id
        self.sensor_type = sensor_type
        self.sensor = self._create_sensor()

    def _create_sensor(self):
        if self.sensor_type == "network":
            return MockNetworkSensor(self.zone_id)
        elif self.sensor_type == "file":
            return MockFileSensor(self.zone_id)
        elif self.sensor_type == "process":
            return MockProcessSensor(self.zone_id)
        else:
            return MockNetworkSensor(self.zone_id)

    def analyze_threat(self, external_event: ThreatEvent) -> ZonalReport:
        sensor_data = self.sensor.read()
        local_score = sensor_data.get("threat_score", 0.0)
        combined = max(external_event.threat_score, local_score)

        if combined >= 0.8:
            verdict = "Malicious"
        elif combined >= 0.4:
            verdict = "Suspicious"
        else:
            verdict = "Benign"

        return ZonalReport(
            zone_id=self.zone_id,
            threat_score=combined,
            local_verdict=verdict,
            details={
                "sensor_type": self.sensor_type,
                "sensor_data": sensor_data,
                "external_event": external_event.to_dict()
            }
        )