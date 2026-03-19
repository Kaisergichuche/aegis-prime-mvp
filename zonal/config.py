# zonal/config.py
import os

ZONE_ID = os.environ.get("ZONE_ID", "room_a")
SENSOR_TYPE = os.environ.get("SENSOR_TYPE", "network")
PORT = int(os.environ.get("PORT", 5001))
MQTT_BROKER_HOST = "localhost"
MQTT_BROKER_PORT = 1883