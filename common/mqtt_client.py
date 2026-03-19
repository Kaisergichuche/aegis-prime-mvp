# common/mqtt_client.py
import paho.mqtt.client as mqtt
import threading
import json
import uuid
from typing import Optional, Dict, Any

class MQTTClient:
    def __init__(self, client_id: str, broker_host: str = "localhost", broker_port: int = 1883):
        self.client = mqtt.Client(client_id)
        self.broker_host = broker_host
        self.broker_port = broker_port
        self._responses = {}
        self._lock = threading.Lock()
        self.client.on_message = self._on_message
        self.client.on_connect = self._on_connect
        self.connected = False

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            print(f"MQTT connected to {self.broker_host}:{self.broker_port}")
        else:
            print(f"MQTT connection failed with code {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            corr_id = payload.get("correlation_id")
            if corr_id:
                with self._lock:
                    if corr_id in self._responses:
                        self._responses[corr_id]["data"] = payload
                        self._responses[corr_id]["event"].set()
        except Exception as e:
            print(f"MQTT message error: {e}")

    def connect(self):
        self.client.connect(self.broker_host, self.broker_port, 60)
        self.client.loop_start()

    def disconnect(self):
        self.client.loop_stop()
        self.client.disconnect()

    def publish(self, topic: str, payload: dict):
        self.client.publish(topic, json.dumps(payload))

    def request(self, target_topic: str, response_topic_base: str, payload: dict, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        corr_id = str(uuid.uuid4())
        response_topic = f"{response_topic_base}/{corr_id}"
        payload["correlation_id"] = corr_id
        payload["response_topic"] = response_topic

        event = threading.Event()
        with self._lock:
            self._responses[corr_id] = {"data": None, "event": event}

        self.client.subscribe(response_topic)
        self.publish(target_topic, payload)

        triggered = event.wait(timeout)
        self.client.unsubscribe(response_topic)
        with self._lock:
            result = self._responses.pop(corr_id, {}).get("data")
        return result if triggered else None