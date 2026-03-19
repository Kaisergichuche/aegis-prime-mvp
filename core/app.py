# core/app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
from core.config import DB_PATH, MQTT_BROKER_HOST, MQTT_BROKER_PORT, ZONES
from core.memory import ThreatMemory
from core.llm_client import LLMClient
from core.orchestrator import Orchestrator
from common.mqtt_client import MQTTClient

app = Flask(__name__)
CORS(app)  # Allow your React app to call these endpoints

# Initialize all components
memory = ThreatMemory(DB_PATH)
llm = LLMClient()
mqtt = MQTTClient("core_ai", broker_host=MQTT_BROKER_HOST, broker_port=MQTT_BROKER_PORT)
mqtt.connect()
orchestrator = Orchestrator(memory, llm, mqtt)

@app.route('/api/trigger', methods=['POST'])
def trigger():
    """Trigger a simulated threat in a specific zone."""
    data = request.json or {}
    zone_id = data.get('zone_id')
    if not zone_id:
        return jsonify({"error": "Missing zone_id"}), 400
    try:
        analysis = orchestrator.trigger_threat(zone_id, data)
        return jsonify({
            "status": "success",
            "threat_id": analysis.threat_id,
            "verdict": analysis.verdict,
            "explanation": analysis.explanation
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def status():
    """Get recent threat analyses."""
    return jsonify(memory.get_recent(20))

@app.route('/api/zones', methods=['GET'])
def zones():
    """List all available zones."""
    return jsonify(ZONES)

@app.route('/api/timeseries', methods=['GET'])
def timeseries():
    """Get threat counts per hour for the last N hours."""
    hours = request.args.get('hours', default=24, type=int)
    return jsonify(memory.get_timeseries(hours))

@app.route('/api/graph/edges', methods=['GET'])
def graph_edges():
    """Get recent network communication edges for graph visualization."""
    limit = request.args.get('limit', default=100, type=int)
    return jsonify(memory.get_graph_edges(limit))

# Optional: serve a simple landing page (you can ignore this if you have React)
@app.route('/')
def index():
    return "<h1>Aegis Insight Core API</h1><p>Use /api/ endpoints</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)