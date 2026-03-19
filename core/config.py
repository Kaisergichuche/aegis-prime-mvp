# core/config.py
import os

# Zones – list of zone IDs (rooms)
ZONES = ["room_a", "room_b", "room_c"]

# Database file path (SQLite)
DB_PATH = os.path.join(os.path.dirname(__file__), "threat_memory.db")

# Ollama settings
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma3:4b"   # you can change to "mistral:7b" if you prefer

# MQTT settings
MQTT_BROKER_HOST = "localhost"
MQTT_BROKER_PORT = 1883
MQTT_REQUEST_TIMEOUT = 5.0   # seconds to wait for Zonal response

# Memory settings
MAX_SIMILAR_EVENTS = 3        # number of similar past events to include in LLM prompt