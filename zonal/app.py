# zonal/app.py
from flask import Flask, jsonify
from flask_cors import CORS
import paho.mqtt.client as paho
import json
from common.models import ThreatEvent, ZonalReport
from zonal.config import ZONE_ID, SENSOR_TYPE, PORT, MQTT_BROKER_HOST, MQTT_BROKER_PORT
from zonal.detector import LocalDetector

app = Flask(__name__)
CORS(app)

detector = LocalDetector(ZONE_ID, SENSOR_TYPE)

request_topic = f"zones/{ZONE_ID}/request"
mqtt_client = paho.Client()
mqtt_client.on_connect = lambda client, userdata, flags, rc: print(f"Zonal {ZONE_ID} MQTT connected")
mqtt_client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, 60)
mqtt_client.subscribe(request_topic)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        corr_id = payload.get("correlation_id")
        resp_topic = payload.get("response_topic")
        if not corr_id or not resp_topic:
            return

        event = ThreatEvent(
            zone_id=payload.get('zone_id', ZONE_ID),
            sensor_type=payload.get('sensor_type', SENSOR_TYPE),
            source_ip=payload.get('source_ip'),
            dest_ip=payload.get('dest_ip'),
            dest_port=payload.get('dest_port'),
            file_path=payload.get('file_path'),
            process_name=payload.get('process_name'),
            threat_score=payload.get('threat_score', 0.0),
            raw_data=payload.get('raw_data'),
            timestamp=payload.get('timestamp')
        )

        report = detector.analyze_threat(event)
        response_dict = report.__dict__
        response_dict["correlation_id"] = corr_id
        mqtt_client.publish(resp_topic, json.dumps(response_dict))
        print(f"Zonal {ZONE_ID} responded to {corr_id}")
    except Exception as e:
        print(f"Zonal {ZONE_ID} error: {e}")

mqtt_client.on_message = on_message
mqtt_client.loop_start()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "zone": ZONE_ID, "sensor": SENSOR_TYPE})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True, use_reloader=False)