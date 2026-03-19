# core/memory.py
import sqlite3
import json
import datetime
from common.models import ThreatEvent, AnalysisResult

class ThreatMemory:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            # Threats table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE,
                    timestamp TEXT,
                    zone_id TEXT,
                    event_data TEXT,
                    analysis TEXT,
                    verdict TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    file_path TEXT,
                    process_name TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON threats(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dest_ip ON threats(dest_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON threats(file_path)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_process_name ON threats(process_name)")

            # Time-series: threat counts per hour
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_timeseries (
                    hour TEXT,
                    threat_count INTEGER DEFAULT 0,
                    zone_id TEXT,
                    PRIMARY KEY (hour, zone_id)
                )
            """)

            # Graph edges for network communications
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    zone_id TEXT,
                    threat_id TEXT,
                    FOREIGN KEY(threat_id) REFERENCES threats(threat_id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_source ON graph_edges(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_dest ON graph_edges(dest_ip)")

    def store_analysis(self, analysis: AnalysisResult):
        with sqlite3.connect(self.db_path) as conn:
            event_dict = analysis.zone_report.to_dict()
            # Insert threat
            conn.execute("""
                INSERT INTO threats (
                    threat_id, timestamp, zone_id, event_data, analysis,
                    verdict, source_ip, dest_ip, dest_port, file_path, process_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis.threat_id,
                analysis.timestamp,
                analysis.zone_report.zone_id,
                json.dumps(event_dict),
                json.dumps({
                    "llm_response": analysis.llm_response,
                    "explanation": analysis.explanation,
                    "similar_events": analysis.similar_past_events
                }),
                analysis.verdict,
                analysis.zone_report.source_ip,
                analysis.zone_report.dest_ip,
                analysis.zone_report.dest_port,
                analysis.zone_report.file_path,
                analysis.zone_report.process_name
            ))

            # Update time-series (hourly count)
            hour = analysis.timestamp[:13] + ":00:00"  # truncate to hour
            conn.execute("""
                INSERT INTO threat_timeseries (hour, zone_id, threat_count)
                VALUES (?, ?, 1)
                ON CONFLICT(hour, zone_id) DO UPDATE SET
                    threat_count = threat_count + 1
            """, (hour, analysis.zone_report.zone_id))

            # If network event, store graph edge
            if analysis.zone_report.source_ip and analysis.zone_report.dest_ip:
                conn.execute("""
                    INSERT INTO graph_edges (timestamp, source_ip, dest_ip, dest_port, zone_id, threat_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    analysis.timestamp,
                    analysis.zone_report.source_ip,
                    analysis.zone_report.dest_ip,
                    analysis.zone_report.dest_port,
                    analysis.zone_report.zone_id,
                    analysis.threat_id
                ))

    def find_similar(self, event: ThreatEvent, limit=3):
        with sqlite3.connect(self.db_path) as conn:
            conditions = []
            params = []
            if event.source_ip:
                conditions.append("source_ip = ?")
                params.append(event.source_ip)
            if event.dest_ip:
                conditions.append("dest_ip = ?")
                params.append(event.dest_ip)
            if event.dest_port:
                conditions.append("dest_port = ?")
                params.append(event.dest_port)
            if event.file_path:
                conditions.append("file_path = ?")
                params.append(event.file_path)
            if event.process_name:
                conditions.append("process_name = ?")
                params.append(event.process_name)
            if not conditions:
                return []
            where_clause = " OR ".join(conditions)
            query = f"""
                SELECT event_data, analysis, verdict, timestamp
                FROM threats
                WHERE {where_clause}
                ORDER BY timestamp DESC LIMIT ?
            """
            params.append(limit)
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "event": json.loads(row[0]),
                    "analysis": json.loads(row[1]),
                    "verdict": row[2],
                    "timestamp": row[3]
                })
            return results

    def get_recent(self, limit=20):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT threat_id, timestamp, zone_id, event_data, analysis, verdict
                FROM threats ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "threat_id": row[0],
                    "timestamp": row[1],
                    "zone_id": row[2],
                    "event": json.loads(row[3]),
                    "analysis": json.loads(row[4]),
                    "verdict": row[5]
                })
            return results

    def get_timeseries(self, hours=24):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT hour, zone_id, threat_count
                FROM threat_timeseries
                ORDER BY hour DESC
                LIMIT ?
            """, (hours,))
            rows = cursor.fetchall()
            return [{"hour": r[0], "zone_id": r[1], "count": r[2]} for r in rows]

    def get_graph_edges(self, limit=100):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT timestamp, source_ip, dest_ip, dest_port, zone_id, threat_id
                FROM graph_edges
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [{
                "timestamp": r[0],
                "source": r[1],
                "target": r[2],
                "port": r[3],
                "zone": r[4],
                "threat_id": r[5]
            } for r in rows]