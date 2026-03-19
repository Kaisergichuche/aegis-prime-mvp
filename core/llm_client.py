# core/llm_client.py
import requests
from core.config import OLLAMA_URL, OLLAMA_MODEL

class LLMClient:
    def __init__(self, model=OLLAMA_MODEL):
        self.model = model
        self.url = OLLAMA_URL

    def analyze(self, prompt):
        try:
            response = requests.post(self.url, json={
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }, timeout=30)
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except Exception as e:
            return f"[ERROR] LLM call failed: {e}"