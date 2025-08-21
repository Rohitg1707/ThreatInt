import os
import requests
from dotenv import load_dotenv 

OTX_BASE = "https://otx.alienvault.com/api/v1"
load_dotenv()

class OTXClient:
    def __init__(self, api_key=None, session=None):
        self.api_key = api_key or os.getenv("OTX_API_KEY")
        if not self.api_key:
            raise ValueError("OTX_API_KEY is required")
        self.session = session or requests.Session()
        self.session.headers.update({"X-OTX-API-KEY": self.api_key})

    def get_subscribed_pulses(self, limit=50, page=1):
        """
        Fetch subscribed pulses (example). Returns JSON list of pulses.
        """
        url = f"{OTX_BASE}/pulses/subscribed"
        params = {"limit": limit, "page": page}
        r = self.session.get(url, params=params, timeout=15)
        r.raise_for_status()
        return r.json()  # contains 'results' etc.

    def get_pulse_indicators(self, pulse_id, limit=100):
        """
        Some OTX responses include indicators in the pulse; if not, you can call another endpoint.
        Keep it simple and assume `pulse['indicators']` exists in returned pulses.
        """
        # placeholder: many pulses already include indicators
        return []
