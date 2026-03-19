# core/orchestrator.py
import uuid
import datetime
from common.models import ThreatEvent, AnalysisResult, ZonalReport
from core.memory import ThreatMemory
from core.llm_client import LLMClient
from core.config import MQTT_REQUEST_TIMEOUT, MAX_SIMILAR_EVENTS

class Orchestrator:
    def __init__(self, memory: ThreatMemory, llm: LLMClient, mqtt_client):
        self.memory = memory
        self.llm = llm
        self.mqtt = mqtt_client

    def trigger_threat(self, zone_id: str, threat_data: dict) -> AnalysisResult:
        # 1. Build ThreatEvent from incoming data
        event = ThreatEvent(
            zone_id=zone_id,
            sensor_type=threat_data.get("sensor_type", "network"),
            source_ip=threat_data.get("source_ip"),
            dest_ip=threat_data.get("dest_ip"),
            dest_port=threat_data.get("dest_port"),
            file_path=threat_data.get("file_path"),
            process_name=threat_data.get("process_name"),
            threat_score=threat_data.get("threat_score", 0.0),
            raw_data=threat_data.get("raw_data"),
            timestamp=datetime.datetime.now().isoformat()
        )

        # 2. Send request to the appropriate Zonal agent via MQTT
        request_topic = f"zones/{zone_id}/request"
        response_base = f"zones/{zone_id}/response"
        payload = event.to_dict()

        zonal_dict = self.mqtt.request(
            target_topic=request_topic,
            response_topic_base=response_base,
            payload=payload,
            timeout=MQTT_REQUEST_TIMEOUT
        )

        if zonal_dict is None:
            # Fallback if Zonal doesn't respond
            zonal_report = ZonalReport(
                zone_id=zone_id,
                threat_score=0.5,
                local_verdict="unknown",
                details={"error": "MQTT timeout or no response"}
            )
        else:
            zonal_report = ZonalReport(**zonal_dict)

        # Update event with the Zonal's threat score
        event.threat_score = zonal_report.threat_score

        # 3. Query memory for similar past events
        similar = self.memory.find_similar(event, limit=MAX_SIMILAR_EVENTS)

        # 4. Build the prompt for the LLM
        prompt = self._build_prompt(event, zonal_report, similar)

        # 5. Call the LLM
        llm_output = self.llm.analyze(prompt)

        # 6. Parse the LLM output (naive parsing)
        verdict, explanation = self._parse_llm_output(llm_output)

        # 7. Create final analysis result
        threat_id = str(uuid.uuid4())
        analysis = AnalysisResult(
            threat_id=threat_id,
            zone_report=event,
            similar_past_events=similar,
            llm_prompt=prompt,
            llm_response=llm_output,
            verdict=verdict,
            explanation=explanation,
            timestamp=datetime.datetime.now().isoformat()
        )

        # 8. Store everything in the database
        self.memory.store_analysis(analysis)

        return analysis

    def _build_prompt(self, event, zonal, similar):
        prompt = f"""You are a cybersecurity AI analyst for a home/office system.
A threat has been detected in zone '{event.zone_id}' with sensor type '{event.sensor_type}'.

Current event details:
"""
        if event.source_ip:
            prompt += f"- Source IP: {event.source_ip}\n"
        if event.dest_ip:
            prompt += f"- Destination IP: {event.dest_ip}\n"
        if event.dest_port:
            prompt += f"- Destination Port: {event.dest_port}\n"
        if event.file_path:
            prompt += f"- File Path: {event.file_path}\n"
        if event.process_name:
            prompt += f"- Process Name: {event.process_name}\n"
        prompt += f"- Local threat score (from zone): {event.threat_score}\n"
        prompt += f"- Zone details: {zonal.details or 'None'}\n"

        if similar:
            prompt += "\nSimilar past events in memory:\n"
            for i, sim in enumerate(similar, 1):
                prompt += f"{i}. Time: {sim['timestamp']}, Verdict: {sim['verdict']}\n"
                prompt += f"   Event: {sim['event']}\n"
                prompt += f"   Analysis: {sim['analysis']['explanation']}\n"
        else:
            prompt += "\nNo similar past events found.\n"

        prompt += """
Based on this information, provide:
1. A verdict: either "Malicious", "Suspicious", or "Benign".
2. A brief explanation (1-2 sentences).

Format your response exactly as:
Verdict: [verdict]
Explanation: [explanation]
"""
        return prompt

    def _parse_llm_output(self, text):
        lines = text.split('\n')
        verdict = "Unknown"
        explanation = text
        for line in lines:
            if line.lower().startswith("verdict:"):
                verdict = line.split(":", 1)[1].strip().capitalize()
            elif line.lower().startswith("explanation:"):
                explanation = line.split(":", 1)[1].strip()
        if verdict not in ["Malicious", "Suspicious", "Benign", "Unknown"]:
            verdict = "Unknown"
        return verdict, explanation